use strict;
use warnings;
use Config;
use POSIX qw(setsid WNOHANG);

sub unavailable {
    print STDERR "HERMES_TERMINAL_SUPERVISOR_UNAVAILABLE\n";
    exit 125;
}

# Linux x86-64 is the only Perl-only agent platform verified for this syscall.
unavailable() unless $Config{archname} =~ /^x86_64-linux/;
my $parent = shift @ARGV;
unavailable() unless defined($parent) && $parent =~ /\A([1-9][0-9]{0,9})\z/ && @ARGV;
$parent = $1;
my $stopping = 0;
$SIG{$_} = sub { $stopping = 1 } for qw(TERM INT HUP);
$SIG{CHLD} = 'DEFAULT';
unavailable() if syscall(157, 36, 1, 0, 0, 0) != 0;
unavailable() if syscall(157, 1, 15, 0, 0, 0) != 0;
my $children = "/proc/$$/task/$$/children";
open(my $probe, '<', $children) or unavailable();
close($probe) or unavailable();
unavailable() if getppid() != $parent || $stopping;

# Perl's taint checks need a safe PATH while starting the shell; restore the
# caller's PATH inside that shell before executing the requested command.
my $has_path = exists($ENV{PATH}) ? '1' : '0';
my $original_path = '';
if ($has_path eq '1') {
    $ENV{PATH} =~ /\A([^\x00\r\n]*)\z/ or unavailable();
    $original_path = $1;
}
$ENV{PATH} = '/usr/bin:/bin';
for (@ARGV) { /\A([^\x00]*)\z/s or unavailable(); $_ = $1; }
my $shell = fork();
unavailable() unless defined $shell;
if ($shell == 0) {
    if (setsid() != -1) {
        eval { exec { '/bin/sh' } '/bin/sh', '-c',
            'if [ "$1" = 1 ]; then PATH=$2; export PATH; else unset PATH; fi; shift 2; exec "$@"',
            'hermes-session', $has_path, $original_path, @ARGV; };
    }
    print STDERR "HERMES_TERMINAL_SUPERVISOR_UNAVAILABLE\n";
    POSIX::_exit(125);
}

my $exit_code = 125;
my $reported = 0;
while (1) {
    if ($stopping) {
        my $ok = open(my $fh, '<', $children);
        my $value;
        if ($ok) {
            $! = 0;
            $value = <$fh>;
            $ok = 0 if !defined($value) && $!;
            $value //= '';
            $ok = 0 unless close($fh);
        }
        if ($ok && defined($value) && $value =~ /\A(?:[0-9]+\s*)*\z/) {
            for my $pid (split /\s+/, $value) {
                next unless length($pid);
                if ($pid !~ /\A([1-9][0-9]{0,9})\z/) { $ok = 0; next; }
                $pid = $1;
                if ($pid <= 1 || (!kill(9, $pid) && !$!{ESRCH})) { $ok = 0; }
            }
        } else { $ok = 0; }
        if (!$ok && !$reported) {
            print STDERR "HERMES_TERMINAL_TERMINATION_INCOMPLETE\n";
            $reported = 1;
        }
    }
    while (1) {
        my $pid = waitpid(-1, WNOHANG);
        if ($pid < 0) {
            exit($stopping ? 143 : $exit_code) if $!{ECHILD};
            last;
        }
        last if $pid == 0;
        $exit_code = ($? & 127) ? 128 + ($? & 127) : $? >> 8 if $pid == $shell;
    }
    select(undef, undef, undef, 0.05);
}
