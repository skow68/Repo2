package App::PaloAlto;
use Moose;
use open IO => ":utf8", ":std";
use utf8;
use strict;
use XML::Simple;
use REST::Client;
use Data::Dumper qw( Dumper );
use 5.10.1;
use Log::Log4perl qw( get_logger );
###Error handling policy###
#dla metod, które wykonują jedną operację (czyli albo się uda, albo nie) zwracana jest wartość undef lub 1.
# dla metod, które mogą udać się częściowo wypełniany jest errstr. W przypadku poprawnie wykonanych funkcji wyszukujących,
# ale bez pozytywnego wyniku zwracany jest undef oraz undef w Errstr. Errstr jest również po to, aby kod wykorzystujący moduł
# mógł zdecydować, co zbłędem zrobić.
# errstr jest też wypełniany, gdy trafi się błąd w odpowiedzi z pa.
# Funkcje wyszukujące: w przypadku braku wyszukiwanego obiektu jest tylko wpis w logu z poziomem debug.
# Do decyzji: Czy tworzymy key dla każdej sesji? Czy konfiguracja z jednego konta administratora, czy każdy ze swojego?
# Raczej z jednego konta. Da się to uzasadnić tym, że i tak konfiguracja jest tworzona automatycznie; osoba administratora
# tylko potwierdza. W Sowie będzie informacja, kto potwierdził.
#Error codes:
#        'P701' => "Error running function against firewall",
#        'P702' => "Invalid argument passed to the module",
#Funkcje zaczynające się od _ nie są uruchamiane zewnętrznie i nie ustawiają errstr.
my $op_cmd = '/api/?type=op&cmd=';
my ($key, $set_cmd, $edit_cmd, $get_cmd, $show_cmd, $delete_cmd);
has 'log' => (is=>'ro',isa=>'Object', builder=>'_builder_log');
has 'host' => (is => 'ro', isa => 'Str');
has 'rest' => (is => 'rw', isa => 'Object', builder => '_builder_rest');
has 'errstr' => (is => 'rw', isa => 'Str', default=>"");
#Inicjacja obiektu nie powinna skutkować błędem. Nie ma w niej niczego takiego, jak bind, connect etc.
#Błędy wynikające z interakcji z firewallem mogą pojawić się dopiero podzas uruchamiania poszczególnych funkcji.
sub BUILD {
        my $self = shift;
        my $args = shift;
        $key = $args->{key};
        my $prefixpath = $args->{xpath};
        $set_cmd = "/api/?type=config&action=set".$prefixpath;
        $edit_cmd = "/api/?type=config&action=edit".$prefixpath;
        $delete_cmd = "/api/?type=config&action=delete".$prefixpath;
        $get_cmd = "/api/?type=config&action=get".$prefixpath;
        $show_cmd = "/api/?type=config&action=show".$prefixpath;
}; #Uwaga: ten średnik jest ważny
sub _builder_log {
    my $self = shift;
    Log::Log4perl::init( './log4pa.conf' );
    return  get_logger();
}
sub _builder_rest {
    my $self = shift;
    my $r = REST::Client->new();
    $r->getUseragent()->ssl_opts(verify_hostname => 0);                                                                        
    $r->getUseragent()->ssl_opts(SSL_verify_mode => 'SSL_VERIFY_NONE');
    $r->setHost('https://'.$self->host);
    return $r;
}
sub find_ip_obj {
    my $self = shift;
    my $ip = shift;
    $self->errstr("");
    my $xp = "address/entry[(contains(translate(ip-netmask, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'".$ip."' )) ]";
    $self->rest->GET($get_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error finding IP $ip: ",Dumper($response));
        $self->errstr("P701");
        return undef;
    }
    if ($response->{code} == 7) {
            $self->log->debug("Can not find IP $ip");
            return undef;
    }
    $self->log->debug( "Found IP object: ",$ip);
    return $response->{result}->{entry}->{name};
}
sub find_fqdn_obj {
    my $self = shift;
    my $fqdn = shift;
    $self->errstr("");
    my $xp = "address/entry[(contains(translate(fqdn, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'".$fqdn."' )) ]";
    $self->rest->GET($get_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error finding FQDN object $fqdn: ",Dumper($response));
        $self->errstr("P701");
        return undef;
    }
    if ($response->{code} eq "7") {
            $self->log->debug("Can not find FQDN object $fqdn");
            return undef;
    }
    $self->log->debug( "Found FQDN object for: ",$fqdn);
    return $response->{result}->{entry}->{name};
}
sub find_ag {
    my $self = shift;
    my $ag = shift;
    $self->errstr("");
    my $xp = "address-group/entry[(contains(translate(\@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'".lc($ag)."' )) ]";
    $self->rest->GET($get_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error trying to find Address Group $ag: ",Dumper($response));
        $self->errstr("P701");
        return undef;
    }
    if ($response->{code} eq "7") {
            $self->log->debug("Address Group does not exist: $ag");
            return undef;
    }
    $self->log->debug( "Found AG object for: ",$ag);
    return $response->{result}->{entry}->{name};
}
sub create_ip_obj {
    my $self = shift;
    my $ip = shift;
    $self->errstr("");
    my $prefix;
    if ($ip =~/\//) {
        $prefix="N-";
    } else {
        $prefix = "H-";
    }
    my $ip_obj = $prefix.$ip;
    $ip_obj =~ s/\//\-/;
    my $xp = "address/entry[\@name='".$ip_obj ."']&element=<ip-netmask>".$ip."</ip-netmask>";
    $self->rest->GET($set_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Can not create IP object $ip_obj: ",Dumper($response));
        $self->errstr("P701");
        return undef; 
    }
    $self->log->debug("New IP object created: ",$ip_obj);
    return $ip_obj;
}
sub find_rule {
    my $self = shift;
    my $rule = shift;
    $self->errstr("");
    my $xp = "rulebase/security/rules/entry[(contains(translate(\@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'".lc($rule)."' )) ]";
    $self->rest->GET($get_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error while finding rule $rule: ",Dumper($response));
        $self->errstr("P701");
        return undef;
    }
    if ($response->{code} eq "7") {
            $self->log->debug("Rule does not exist: $rule");
            return undef;
    }
    $self->log->debug( "Found Rule object for: ",$rule);
    #$response->{result}->{entry}->{name};
    return 1;
}
sub create_rule {
    my $self = shift;
    my $arg = shift;
    $self->errstr("");
    my $xp = "rulebase/security/rules/entry[\@name='".$arg->{name}."']&element=";
    my $element = "<to><member>".$arg->{to}."</member></to><from><member>".$arg->{from}."</member></from><source><member>any</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>allow</action>";
    $self->rest->GET($set_cmd.$xp.$element.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error creating security rule $arg->{name}: ",Dumper($response));
        $self->errstr("P701");
        return undef; 
    }
    $self->log->debug("New security rule created: ",$arg->{name});
    return 1;
}
sub delete_rule {
    my $self = shift;
    my $arg = shift;
    $self->errstr("");
    my $xp = "rulebase/security/rules/entry[\@name='".$arg."']";
    $self->rest->GET($delete_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error deleting security rule $arg: ",Dumper($response));
        $self->errstr("Błąd podczas usuwania reguły $arg");
        return undef; 
    }
    $self->log->debug("Security rule deleted: ",$arg);
    return 1;
}
sub groupmap {
    my $self = shift;
    my $group = shift;
    $self->errstr("");
    my $xp = "group-mapping/entry[\@name='CN']&element=";
    my $element = "<group-include-list><member>cn=".$group.",ou=8021xlan,ou=network access control,DC=project,DC=com,DC=pl</member></group-include-list>";
    $self->rest->GET($set_cmd.$xp.$element.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error creating group map for $group: ",Dumper($response));
        $self->errstr("P701");
        return undef; 
    }
    $self->log->debug("New group map created: ",$group);
    return 1;
}
sub add_users {
        #dodaje user group do reguły
    my $self = shift;
    my $rule = shift;
    my $group = shift;
    my $xml;
    $self->errstr("");
    foreach my $g (@{$group}) {
        return 0 if (! $self->groupmap($g) );
        $xml = $xml."<member>$g</member>";
    }
    my $xp ="rulebase/security/rules/entry[\@name='".$rule."']/source-user&element=";
    my $element = "<source-user>$xml</source-user>";
    $self->rest->GET($edit_cmd.$xp.$element.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error modifying user group in rule: $rule: ",Dumper($response),$xp,$element);
        $self->errstr("P701");
        return undef; 
    }
    $self->log->debug("Security rule modified: ",$rule);
    return 1;
}
sub add_dest {
        #dodaje address group do reguły
    my $self = shift;
    my $rule = shift;
    my $group = shift;
    $self->errstr("");
    $self->find_ag($group) || $self->create_ag($group) || return undef;
    my $xp ="rulebase/security/rules/entry[\@name='".$rule."']/destination&element=";
    my $element = "<destination><member>".$group."</member></destination>";
    $self->rest->GET($edit_cmd.$xp.$element.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error modifying destination in rule $rule: ",Dumper($response));
        $self->errstr("P701");
        return undef; 
    }
    $self->log->debug("Security rule modified: ",$rule);
    return 1;
}
sub create_fqdn_obj {
    my $self = shift;
    my $fqdn = shift;
    $self->errstr("");
    my $xp = "address/entry[\@name='".$fqdn ."']&element=<fqdn>".$fqdn."</fqdn>";
    $self->rest->GET($set_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error creating FQDN object $fqdn: ",Dumper($response));
        $self->errstr("P701");
        return undef; 
    }
    $self->log->debug("New IP object created: ",$fqdn);
    return $fqdn;
}
sub _add_ag_member {
    my $self = shift;
    my $ag = shift;
    my $xp = "address-group/entry[\@name='".$ag->{group}."']/static&element=<member>".$ag->{ip_obj}."</member>";
    $self->rest->GET($set_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error adding $ag->{ip_obj} to address group $ag->{group} ",Dumper($response));
        return undef; 
    }
    $self->log->debug("IP object added to Address Group: ",$ag->{group}," ". $ag->{ip_obj});
    return 1;
}
sub create_ag {
    my $self = shift;
    my $ag = shift;
    my $xp = "address-group&element=<entry name='".$ag."'/>";
    $self->rest->GET($set_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error creating Address Group $ag: ",Dumper($response));
        $self->errstr("P701");
        return undef; 
    }
    $self->log->debug("Address Group created: ",$ag);
    return 1;
}
sub delete_ag {
    my $self = shift;
    my $arg = shift;
    $self->errstr("");
    my $xp = "address-group/entry[\@name='".$arg."']";
    $self->rest->GET($delete_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error deleting AG $arg: ",Dumper($response));
        $self->errstr("P701");
        return undef; 
    }
    $self->log->debug("AG deleted: ",$arg);
    return 1;
}
sub commit {
    #Zakładamy, że zawsze api jest wykorzystywany przez adminapi
    my $self = shift;
    $self->errstr("");
    my $xp="/api/?type=commit&action=partial&cmd=<commit><partial><admin><member>adminapi</member></admin></partial></commit>";
    $self->rest->GET($xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Commit failed: ",Dumper($response));
        $self->errstr("P701");
        return undef; 
    }
    my $jobid = 0;
    my $i=0;
    until ($jobid || $i > 3) {
        sleep 1;
        $i++;
        $jobid = $response->{result}->{job};
    };
    $xp = "/api/?type=op&cmd=<show><jobs><id>".$jobid."</id></jobs></show>";
    $i=0;
    do { 
        sleep 3;
        $i++;
        $self->rest->GET($xp.$key); 
        $response = XMLin($self->rest->responseContent());
    } while  ($response->{result}->{job}->{result} eq "PEND" || $i>7); 
    if ($response->{result}->{job}->{result} eq "OK") {
        $self->log->debug("Commit successful");
        return 1;
    }
    $self->log->error("Commit failed: ",Dumper($response));
    $self->errstr("P701");
    return undef;
}
sub add_ag_member {
        #dodaje listę adresów do ag
    #args: addresy => ref_to_array, group => ag_name
    my $self = shift;
    my $arg = shift;
    $self->errstr("");
    my $obj;
    my $res = 1;
    my $error = 1;
        #zakładamy, że jeśli uda się dodac chociaż jednego usera to fukcja kończy się sukcesem
    (! $self->find_ag($arg->{group})) and $res = $self->create_ag($arg->{group});
    return undef if ! $res;   
    foreach my $m (@{$arg->{adresy}}) {
        chomp ($m);
        if ($m =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/\d{1,2})?$/) {
            $obj = $self->find_ip_obj($m) || $self->create_ip_obj($m);
        } elsif ($m =~ /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/){
            $obj = $self->find_fqdn_obj($m) || $self->create_fqdn_obj($m);
        } else {
           $self->log->error( "Invalid address while adding to AG: $m");
           $self->errstr("Nieprawidłowy adres - $m");
        }
        next if (! $obj);
        if (! $self->_add_ag_member({group=>$arg->{group},ip_obj => $obj}) ) {
           $self->errstr("Nie wszystkie adresy udało się dodać do grupy $arg->{group} na firewall'u");
        } else {
                $error = 0;
        }
    } 
    $error?return 0:return 1;
}
sub del_ag_member {
        #usuwa listę adresów z ag
    #args: addresy => ref_to_array, group => ag_name
    my $self = shift;
    my $arg = shift;
    my $error = 1;
    #zakładamy, że jeśli uda się usunąć chociaż jeden adres to fukcja kończy się sukcesem
    foreach my $m (@{$arg->{adresy}}) {
        chomp ($m);
        if ($m =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/\d{1,2})?$/) {
            my $prefix;
            if ($m =~/\//) {
                $prefix="N-";
                $m =~ s/\//\-/;
            } else {
                $prefix = "H-";
            }
            $m = $prefix.$m;
        } elsif ($m =~ /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/){
        } else {
           $self->log->error( "Invalid addres while removing from AG: $m");
           $self->errstr("Nieprawidłowy adres - $m");
           next;
        }
        if ($self->_del_ag_member({group=>$arg->{group},ip_obj => $m}) ) {
                $error = 0;
        } else {
           $self->errstr("Nie wszystkie adresy udało się usunąć z grupy $arg->{group} na firewall'u");
        }
    }
    $error?return 0:return 1
}
        
sub _del_ag_member {
    my $self = shift;
    my $ag = shift;
    my $xp = "address-group/entry[\@name='".$ag->{group}."']/static/member[text()='".$ag->{ip_obj}."']";
    $self->rest->GET($delete_cmd.$xp.$key); 
    my $response = XMLin($self->rest->responseContent());
    if ($response->{status} eq "error") {
        $self->log->error("Error deleting $ag->{ip_obj} from address group $ag->{group}",Dumper($response));
        return undef; 
    }
    $self->log->debug("IP object removed from Address Group: ",$ag->{group}, $ag->{ip_obj});
    return 1;
}
sub import_addr_group {
    #Error handling: nie zwracamy do caller'a szczegółów, który IP nie został dodany.
    #Zakładamy, że poszuka sobie w logach
    my $self = shift;
    my $arg = shift;
    my $obj;
    if (! open(INPUT,$arg->{file})) {
       $self->log->error( "File with IPs ".$arg->{file}." can't be found !");
       return undef;
    } 
    if (! $self->find_ag($arg->{group}) ) {
        if (! $self->create_ag($arg->{group})) {
               return undef;
       }
    }     
    while (defined(my $line = <INPUT>)) {  
        chomp ($line);
        if ($line =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/\d{1,2})?$/) {
            $obj = $self->find_ip_obj($line) || $self->create_ip_obj($line);
        } elsif ($line =~ /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/){
            $obj = $self->find_fqdn_obj($line) || $self->create_fqdn_obj($line);
        } else {
           $self->log->error( "Invalid name: $line");
        }

        #if (! $ip_obj) {
        #        $ip_obj = $self->create_ip_obj($ip_obj);
        #}
        if (! $obj) {
           next;
        }
        if ($self->_add_ag_member({group=>$arg->{group},ip_obj => $obj}) ) {
           return 1;
        } else {
            return undef;
        }
    }

}
__PACKAGE__->meta->make_immutable;
1;
