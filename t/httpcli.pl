#! /usr/bin/env perl

use strict;
use warnings;
use Getopt::Std;
use WWW::Curl::Easy;
use WWW::Curl::Multi;
use Data::Dumper;
use Time::HiRes qw(usleep);

my %statis = ();

#=====================================================
# Command-line arguements processing
#=====================================================
(my $myname = $0) =~ s|.*/||;

our ($opt_h, $opt_u, $opt_n);

getopts("h:u:n:") or die <<EOF;

  Usage:  $myname [options]
      -h            http header host
      -u            url 
      -n            total access times, when it less then 1000,
                    it will be set 1000.

EOF


srand;

my $url = $opt_u || "http://localhost/";
my $curl_multi = WWW::Curl::Multi->new;
my $curl_id = 1;
my %curl_handlers;
my %response;
my $active_handlers = 0;

my $total_num = $opt_n || 1000000;
my $once_num = 1000;
my $times = int(($total_num + $once_num - 1) / $once_num);

for (my $j = 0; $j < $times; ++$j) {
    for (my $i = 0; $i < 1000; ++$i) {
        my $range = int(rand(10000000000));
        my $curl = WWW::Curl::Easy->new;
        $curl->setopt(CURLOPT_PRIVATE, $curl_id);
        $curl->setopt(CURLOPT_URL, $url);
        if (defined($opt_h) && $opt_h ne "") {
            $curl->setopt(CURLOPT_HTTPHEADER, ["Host: $opt_h"]);
        }
        $curl->setopt(CURLOPT_HTTPHEADER, ["Range: bytes=$range-"]);
        $curl->setopt(CURLOPT_TIMEOUT, 5);
        $curl->setopt(CURLOPT_HEADER, 1);
        open (my $fileb, ">", \$response{$curl_id});
        $curl->setopt(CURLOPT_WRITEDATA, $fileb);
        $curl_handlers{$curl_id} = $curl;
    
        $curl_multi->add_handle($curl);
        ++$curl_id;
        ++$active_handlers;
    }
    
    
    while ($active_handlers) {
        my $active = $curl_multi->perform;
        unless ($active != $active_handlers) {
            usleep(100);
            next;
        }
    
        while (my ($id, $ret) = $curl_multi->info_read) {
            if ($id) {
                --$active_handlers;
                my $handler = $curl_handlers{$id};
                my $httpcode = $handler->getinfo(CURLINFO_HTTP_CODE);
                if ($ret == 0 && $httpcode == 302) {
                    my $res = $response{$id};
                    my @res = split(/\r\n/,  $res);
                    my @temp = grep /^Location:/i, @res;
                    $temp[0] =~ m/Location: http:\/\/([^\/]*)\/(.*)/;
                    ++$statis{$1};
                } else {
                    print "ERROR: http:$httpcode, curlcode:" . $handler->strerror($ret), "\n";
                }
    
                delete $curl_handlers{$id};
            }
        }
    }
}

while (my ($key, $value) = each %statis) {
    print "$value: $key\n";
}
