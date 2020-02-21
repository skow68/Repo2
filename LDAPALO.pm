package App::LDAPALO;
use Moose;
use open IO => ":utf8", ":std";
use utf8;
use strict;
use XML::Simple;
use Net::LDAP;
use Log::Log4perl qw( get_logger );
use Data::Dumper qw( Dumper );
use 5.10.1;
#our $base_cn = "DC=cn,DC=in,DC=project,DC=com,DC=pl";
#our $base_br = "DC=br,DC=in,DC=project,DC=com,DC=pl";
Log::Log4perl::init( './log4pa.conf' );
our $log = get_logger();
#has 'log' => (is=>'ro',isa=>'Object', builder=>'_builder_log');
has 'group' => (isa => 'Str', is => 'ro'); #na tym parametrze opiera się obiekt
has 'domain' => (isa => 'Str', is => 'ro');
has 'gname' => (isa => 'Str', is => 'ro');
has 'ldap' => (is=>'ro',isa=>'Object', lazy =>1, builder=>'_builder_ldap');
has 'dn' => (isa => 'Str', is => 'rw');
has 'create' => (is => 'rw', isa => 'Bool', default => 0);
has 'error' => (is => 'rw', isa => 'Str', default => "");
#W odróżnieniu od procedury, która może zwrócić prawidłowość swojego działania za pomoca return, inicjacja obiektu nie
#ma takiej możliwości. Można w BUILD lub w builderze użyć die i kodzie głównym wyłapać ten błąd. Można również zastosować atrybut obiektu,
#który będzie zawierał informację o błędzie (tutaj 'error'). Kod główny będzie musiał sprawdzać ten atrybut po inicjacji obiektu.
around BUILDARGS => sub {
    my ($orig, $class, $args) = @_;
    my ( $domain, $groupname ) = split( /\\/, $args->{group});
    return $class->$orig(
        domain => lc $domain,
        gname => lc $groupname,
        create => $args->{create} //0
    )
}; #Uwaga: ten średnik jest ważny
sub BUILD {
    #Ustawiany jest parametr dn = distinguished name grupy
    #Jesli grupy jeszcze nie ma i parametr create=1, to grupa jest tworzona.
    #Jeśli grupy nie ma i create=0, to dn = 0
    #Jeśli błąd, to dn=0 i ustawiany jest error
    my $self = shift;
    my $base =  'OU=FW-ACCESS,OU=Network Access Control,DC='.$self->domain.',DC=in,DC=project,DC=com,DC=pl';
    $log->debug("Search dn for " . $self->gname . " in ". $self->domain);
    my $result       = $self->ldap->search(
        base   => $base,
        filter => 'cn='.$self->gname,
        attrs  => ['distinguishedName'] );
    if ( $result->count < 1 && $self->create) {
        $log->info("Creating group". $self->gname);
        my $dn = 'CN='.$self->gname.','.$base;
        my $resadd = $self->ldap->add ($dn, attrs => [
                  objectClass => ["top","group"],
                  name => $self->gname,
                  cn => [$self->gname],
                  sAMAccountName => $self->gname,
        ]);
        if ($resadd->code) {
                $log->error( "Failed to add group ".$self->gname.": ", $resadd->error);
                $self->error("Błąd podczas tworzenia grupy domenowej ".$self->gname);
                return 0;
        }
        $self->dn($dn); #zwracany, jeśli add się udało; w przecwnym wypadku zwracane 0
    } elsif ($result->count > 0) {
        $self->dn( $result->entry->get_value('distinguishedName') );
    } else {
            return 0;
    }
};

sub _builder_ldap {
    my $self = shift;
    $log->debug("Computed domain: ",$self->domain);
    my ($ldap, $mesg);
    my $config = XMLin( '/home/paloauto/config.xml', KeyAttr => '' );
    if ($self->domain eq "dm1") {
            $ldap = Net::LDAP->new( $config->{ldap_dm1} ) or die "$@";
            $mesg = $ldap->bind(
                $config->{ldap_bind},
                # password => $config{ldap_passwd},
                
                password => '******',
                version  => 3 );
    }
    if ($self->domain eq "dm2") {
            $ldap = Net::LDAP->new( $config->{ldap_dm2} ) or die "$@";
            $mesg = $ldap->bind(
                $config->{ldap_bind},

                # password => $config{ldap_passwd},
                password => '***********',
                version  => 3 );
    }
    $mesg->code and $log->error("LDAP connection failed: ". $mesg->error );
    #Nie ustawia błędu. Ponieważ ta funkcja jest lazy, to jest uruchamiana z BUILD.
    #Jest tam uruchamiana funkcja search, po której dopiero jest ustawiany błąd.
    return $ldap;
}
sub user_dn { #bedzie potrzebna do dodawania usera do grupy
    my $self = shift;
    my $user = shift;
    my ( $domain, $uname ) = split( /\\/, $user);
    $log->debug("Search dn for " . $user . " in ". $self->domain);
    my $result       = $self->ldap->search(
        base   => "DC=".$self->domain.",DC=in,DC=project,DC=com,DC=pl",
        filter => 'samaccountname='.$uname,
        attrs  => ['distinguishedName'] );
    if ( $result->count < 1 ) {
        $log->error("Nie znaleziono podanego konta użytkownika: ",$user);
        return 0
    } else {
        return $result->entry->get_value('distinguishedName');
    }
};
sub create_group {
        #do skasowania
    my $self = shift;
    my $group = $self->group;
    my $dn = 'CN='.$group.',OU=FW-ACCESS,OU=Network Access Control,DC='.$self->domain.',DC=in,DC=project,DC=com,DC=pl';
    my $result = $self->ldap->add ($dn, attrs => [
          objectClass => ["top","group"],
          name => $group,
          cn => [$group],
          sAMAccountName => $group,
    ]);
    if ($result->code) {
        $log->error( "Failed to add group $group: ", $result->error);
        return 0;
    }
    return 1;
}
sub delete_group {
    my $self = shift;
    my $group = $self->gname;
    my $dn = 'CN='.$group.',OU=FW-ACCESS,OU=Network Access Control,DC='.$self->domain.',DC=in,DC=project,DC=com,DC=pl';
    my $result = $self->ldap->delete($dn);
    if ($result->code) {
        $log->error( "Failed to delete group $group: ", $result->error);
        return 0;
    }
    $log->debug("Domain group deleted ".$self->gname);
    return 1;
}
sub find_group {
    my $self = shift;
    $log->debug("Searching for " , $self->gname );
    my $attrs = [ 'cn'];
    my @ret;
    my $result       = $self->ldap->search(
        base   => "OU=FW-ACCESS,OU=Network Access Control,DC=".$self->domain.",DC=in,DC=project,DC=com,DC=pl",
        filter => 'samaccountname='.$self->gname,
        attrs  => $attrs );
    if ( $result->count < 1 ) {
        $log->debug("Domain group not found ".$self->gname);
        return 0
    } else {
        $log->debug("Domain group found ".$self->gname);
        return 1;
    }
}
sub add_user {
        #dodaje lstę userów do grupy
    my $self = shift;
    my $userset = shift; #ref do listy
    my $error = 1;
    foreach my $u (@{$userset}) {
        my $udn = $self->user_dn($u);
        my $gdn = $self->dn;
        $log->debug("Adding ".$udn." to the group ".$self->gname);
        my $msg = $self->ldap->modify($gdn, add => {member => $udn});
        #zakładamy, że jeśli uda się dodac chociaż jednego usera to fukcja kończy się sukcesem
        if ($msg->is_error) {
                $log->error("LDAP error: ", $msg->error_desc);
                if ($msg->error_desc =~ /Already/) {
                    $error = 0;
                } else {
                    $self->error("Nie wszystkie konta udało się dodać do grupy domenowej ".$self->gname);
                }
        } else {
            $error = 0;
        }
    }
    #$self->ldap->unbind;
    $error and $self->error("Błąd: nie udało się dodać uzytkowników do grupy domenowej ".$self->gname);
    $error?return 0:return 1;
}
sub del_user {
        #usuwa listę userów z grupy
    my $self = shift;
    my $userset = shift; #ref do listy
    my $error = 1;
    foreach my $u (@{$userset}) {
        my $udn = $self->user_dn($u);
        my $gdn = $self->dn;
        $log->debug("Deleting ".$udn." from the group ".$self->gname);
        my $msg = $self->ldap->modify($gdn, delete => {member => $udn});
        #zakładamy, że jeśli uda się usunąć chociaż jednego usera to fukcja kończy się sukcesem
        if ($msg->is_error) {
                $log->error("LDAP error: ", $msg->error_desc);
                #eval {$self->ldap->unbind};
                if ($msg->error_desc =~ /Already/) {
                    $error = 0;
                }
        } else {
            $error = 0;
        }
    }
    #$self->ldap->unbind;
    $error?return 0:return 1
}

__PACKAGE__->meta->make_immutable;
1;
