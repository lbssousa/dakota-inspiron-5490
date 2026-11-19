#!/usr/bin/bash
# Exercises yubikey-manage (the `ujust yubikey-*` recipes) inside the built
# image, with the security key stubbed: fido2-token, fido2-assert, pamu2fcfg,
# `ssh-keygen -K` and the OpenPGP card (`gpg --card-status`). gpg, ssh, python3
# and gum's callers are the image's own. PAM files, keys and keyrings live in a
# temporary directory; nothing on the image is changed. CI runs it as:
#
#   podman run --rm --network none -v "$PWD/tests:/tests:ro" \
#     --entrypoint /usr/bin/bash <image> /tests/yubikey-manage-test.sh
# check takes its condition in single quotes, evaluated later; the card URL
# is written escaped, as gpg prints it.
# shellcheck disable=SC2016,SC2028,SC2034
set -uo pipefail
script=${YUBIKEY_MANAGE:-/usr/libexec/dakota-inspiron-5490/yubikey-manage}
justfile=${YUBIKEY_JUSTFILE:-/usr/share/ublue-os/just/60-custom.just}
T=$(mktemp -d)
export HOME=$T/home USER=tester XDG_RUNTIME_DIR=$T/run
mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$T/stubs" "$T/etc" "$T/lib"
chmod 700 "$XDG_RUNTIME_DIR"
fails=0
pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'NOT OK - %s\n' "$*"; fails=$((fails + 1)); }
check() { if eval "$1"; then pass "$2"; else fail "$2"; fi; }

stub() { printf '#!/usr/bin/bash\n%s\n' "$2" >"$T/stubs/$1"; chmod +x "$T/stubs/$1"; }
# gum: confirm answers $GUM_CONFIRM (0 = yes), choose picks the first option
# matching $GUM_CHOOSE, input prints $GUM_INPUT, style prints its text.
stub gum 'case $1 in
confirm) exit "${GUM_CONFIRM:-0}" ;;
choose) shift; while [[ $1 == --* ]]; do shift 2; done
  for o in "$@"; do [[ $o == *"${GUM_CHOOSE:-}"* ]] && { echo "$o"; exit 0; }; done; exit 1 ;;
input) echo "${GUM_INPUT:-0}" ;;
style) shift; while [[ $1 == --* ]]; do [[ $1 == --bold ]] && shift || shift 2; done; echo "$*" ;;
esac'
# A key at /dev/hidraw0, with a PIN unless $T/nopin exists. Its credentials
# are the handles listed in $T/key-handles; pamu2fcfg makes $T/next-handle.
stub fido2-token "[[ -e $T/nokey ]] && exit 0
case \$1 in
-L) echo '/dev/hidraw0: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)' ;;
-I) [[ -e $T/nopin ]] && echo 'options: rk, up, noplat, noclientPin' || echo 'options: rk, up, noplat, clientPin, credMgmt' ;;
esac"
stub fido2-assert "read -r _; read -r origin; read -r handle; [[ \$origin == pam://* ]] || exit 3; grep -qx \"\$handle\" $T/key-handles"
stub pamu2fcfg "h=\$(<$T/next-handle); echo \"\$h\" >>$T/key-handles; echo \"\$*\" >$T/pamu2fcfg-args; echo \"tester:\$h,PUBKEY\$h,es256,+presence\""
# ssh-keygen -K writes the resident keys of $T/resident (application per line).
stub ssh-keygen "[[ \$1 == -K ]] || exec /usr/bin/ssh-keygen \"\$@\"
while read -r app; do
  python3 -I - \"\$app\" <<'PY'
import base64, os, sys
s = lambda b: len(b).to_bytes(4, 'big') + b
app = sys.argv[1]
blob = s(b'sk-ssh-ed25519@openssh.com') + s(os.urandom(32)) + s(app.encode())
name = 'id_ed25519_sk_rk' + ('_' + app[4:] if app[4:] else '')
open(name, 'w').write('-----BEGIN OPENSSH PRIVATE KEY-----\nhandle\n-----END OPENSSH PRIVATE KEY-----\n')
open(name + '.pub', 'w').write('sk-ssh-ed25519@openssh.com ' + base64.b64encode(blob).decode() + ' tester@host\n')
PY
done <$T/resident"
export PATH="$T/stubs:$PATH"
tty_run() { script -qec "$(printf '%q ' "$@")" /dev/null </dev/null; }

# ---- U2F ----
export YUBIKEY_PAM_DIRS="$T/etc $T/lib"
printf 'auth sufficient pam_rootok.so\nauth include system-auth\n' >"$T/etc/sudo"
printf 'auth include system-auth\naccount include system-auth\n' >"$T/lib/polkit-1"
printf 'auth        required      pam_env.so\nauth        sufficient    pam_fprintd.so\nauth       sufficient   pam_u2f.so cue nouserok\nauth        sufficient    pam_unix.so try_first_pass nullok_secure\n' >"$T/etc/system-auth"
authfile=$HOME/.config/Yubico/u2f_keys
: >"$T/key-handles"

out=$("$script" u2f status 2>&1)
check '[[ $out == *"accept a registered key"* && $out == *"A touch is enough"* && $out == *"No keys registered"* ]]' "u2f status reads pam_u2f through include: $out"

echo H1 >"$T/next-handle"
out=$(tty_run "$script" u2f register 2>&1)
check '[[ $(<"$authfile") == "tester:H1,PUBKEYH1,es256,+presence" && $(stat -c %a "$authfile") == 600 ]]' "register writes the user's line, 0600: $out"
check '[[ $(<"$T/pamu2fcfg-args") == "-u tester " || $(<"$T/pamu2fcfg-args") == "-u tester" ]]' "no origin options without origin= in PAM"

echo H1X >"$T/next-handle"
out=$(tty_run "$script" u2f register 2>&1)
check '[[ $out == *"already registered"* && $(<"$authfile") == "tester:H1,PUBKEYH1,es256,+presence" ]]' "the same key isn't registered twice: $out"

# A second key: the first one's handle no longer answers.
echo other:X1,P,es256,+presence >"$authfile.tmp"; cat "$authfile" >>"$authfile.tmp"; mv "$authfile.tmp" "$authfile"; chmod 600 "$authfile"
: >"$T/key-handles"; echo H2 >"$T/next-handle"
tty_run "$script" u2f register >/dev/null 2>&1
check '[[ $(grep ^tester: "$authfile") == "tester:H1,PUBKEYH1,es256,+presence:H2,PUBKEYH2,es256,+presence" && $(grep -c ^other: "$authfile") == 1 ]]' "a second key joins the same line, other users' lines kept"

out=$(GUM_CHOOSE="(the key plugged in)" tty_run "$script" u2f remove 2>&1)
check '[[ $(grep ^tester: "$authfile") == "tester:H1,PUBKEYH1,es256,+presence" ]]' "remove marks the key plugged in and drops the one picked: $out"

out=$(tty_run "$script" u2f pin-on 2>&1)
check 'grep -qx "auth sufficient pam_u2f.so cue nouserok userpresence=1 pinverification=1" "$T/etc/system-auth" && ls "$T/etc"/system-auth.yubikey-* >/dev/null' "pin-on sets the options on system-auth's line, with a backup: $out"
out=$("$script" u2f status 2>&1)
check '[[ $out == *"ask for the key'"'"'s PIN"* ]]' "status sees the PIN on"
out=$(tty_run "$script" u2f pin-off 2>&1)
check 'grep -qx "auth sufficient pam_u2f.so cue nouserok userpresence=1" "$T/etc/system-auth"' "pin-off drops pinverification"
touch "$T/nopin"
out=$(tty_run "$script" u2f pin-on 2>&1)
check '[[ $out == *"no PIN"* ]] && ! grep -q pinverification "$T/etc/system-auth"' "pin-on refused for a key without a PIN: $out"
rm "$T/nopin"

sed -i 's|pam_u2f.so cue|pam_u2f.so cue authfile=/etc/fido2/fido2|' "$T/etc/system-auth"
out=$(tty_run "$script" u2f register 2>&1)
check '[[ $out == *"an administrator has to register"* ]]' "register refused when PAM reads another file: $out"
sed -i 's|pam_u2f.so cue authfile=/etc/fido2/fido2|pam_u2f.so cue origin=pam://dakota appid=pam://dakota|' "$T/etc/system-auth"
: >"$T/key-handles"; echo H3 >"$T/next-handle"
tty_run "$script" u2f register >/dev/null 2>&1
check '[[ $(<"$T/pamu2fcfg-args") == "-u tester -o pam://dakota -i pam://dakota" ]]' "register passes PAM's origin and appid to pamu2fcfg: $(<"$T/pamu2fcfg-args")"

sed -i '/pam_u2f/d' "$T/etc/system-auth"
out=$(GUM_CONFIRM=1 tty_run "$script" u2f register 2>&1)
check '[[ $out == *"don'"'"'t ask for a key yet"* ]]' "register warns when PAM has no pam_u2f, and stops on no"

# ---- SSH ----
mkdir -p "$HOME/.ssh"; printf 'Host *\n    ServerAliveInterval 30\n' >"$HOME/.ssh/config"; chmod 600 "$HOME/.ssh/config"
printf 'ssh:github.com\nssh:\n' >"$T/resident"
out=$(GUM_INPUT=30 tty_run "$script" ssh import 2>&1)
check '[[ -f $HOME/.ssh/id_ed25519_sk_rk_github.com && -f $HOME/.ssh/id_ed25519_sk_rk_github.com.pub && $(stat -c %a $HOME/.ssh/id_ed25519_sk_rk_github.com) == 600 ]]' "import installs the github.com pair: $out"
check '[[ -f $HOME/.ssh/id_ed25519_sk_rk && $(head -n1 $HOME/.ssh/config) == "Include config.d/*.conf" && $(grep -c ServerAliveInterval $HOME/.ssh/config) == 1 ]]' "the key with no application too, Include on top of the config"
conf=$HOME/.ssh/config.d/github.com.conf
check 'grep -qx "    IdentityFile ~/.ssh/id_ed25519_sk_rk_github.com" "$conf" && grep -qx "    User git" "$conf" && grep -qx "    ControlPersist 30m" "$conf" && [[ -d $HOME/.ssh/yubikey/control ]]' "github.com set up, connections reused 30m"
check 'ssh -G -F "$HOME/.ssh/config" github.com | grep -qi "^identitiesonly yes"' "ssh reads the setup for github.com"

echo keep >"$HOME/.ssh/id_ed25519_sk_rk_github.com.pub.keep"
out=$(tty_run "$script" ssh import 2>&1)
check '[[ $out == *"Kept the ~/.ssh/id_ed25519_sk_rk_github.com"* ]]' "import never overwrites a copy already there: $out"

out=$("$script" ssh status 2>&1)
check '[[ $out == *"ssh:github.com → github.com, connections reused for 30m"* ]]' "status shows the host: $out"

out=$(GUM_INPUT=0 GUM_CHOOSE=github tty_run "$script" ssh host 2>&1)
check 'grep -qx "    ControlPersist no" "$conf"' "host changes the connection reuse: $out"

echo "# my edit" >>"$conf"
out=$("$script" ssh status 2>&1)
check '[[ $out == *"set up by hand"* ]]' "a hand-edited host file is left alone: $out"
sed -i '/# my edit/d' "$conf"

out=$(GUM_CHOOSE=github tty_run "$script" ssh remove 2>&1)
check '[[ ! -e $HOME/.ssh/id_ed25519_sk_rk_github.com && ! -e $conf && -f $HOME/.ssh/id_ed25519_sk_rk ]]' "remove deletes the copy and its host file: $out"

# ---- GPG ----
export GNUPGHOME=$HOME/.gnupg; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
src=$T/src; mkdir -p "$src"; chmod 700 "$src"
gpg --homedir "$src" --batch --passphrase '' --quick-gen-key 'Card Owner <owner@example.org>' ed25519 sign 0 2>/dev/null
fpr=$(gpg --homedir "$src" --list-keys --with-colons | awk -F: '$1=="fpr"{print $10; exit}')
gpg --homedir "$src" --batch --quick-add-key "$fpr" cv25519 encr 0 2>/dev/null
enc=$(gpg --homedir "$src" --list-keys --with-colons | awk -F: '$1=="fpr"{n++} $1=="fpr" && n==2 {print $10}')
mkdir -p "$T/www"; gpg --homedir "$src" --armor --export "$fpr" >"$T/www/key.asc"
gpg --homedir "$src" --batch --passphrase '' --quick-gen-key 'Someone Else' ed25519 sign 0 2>/dev/null
other=$(gpg --homedir "$src" --list-keys --with-colons | awk -F: '$1=="fpr"{print $10}' | tail -1)
gpg --homedir "$src" --armor --export "$other" >"$T/www/wrong.asc"
(cd "$T/www" && exec python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1) &
server=$!
sleep 1
real_gpg=$(command -v gpg)
stub gpg "if [[ \" \$* \" == *' --card-status '* ]]; then
  [[ -e $T/nocard ]] && exit 2
  printf 'Reader:1050:0407:X:AID:D2760001240103040006123456780000:openpgp-card:\nname:Card:Owner:\nurl:%s:\nfpr:$fpr:$enc::\n' \"\$(<$T/url)\"
  exit 0
fi
[[ \" \$* \" == *' --recv-keys '* ]] && exit 2
exec $real_gpg \"\$@\""
echo 'http\x3a//127.0.0.1\x3a8765/wrong.asc' >"$T/url"
out=$(tty_run "$script" gpg import 2>&1)
check '[[ $out == *"doesn'"'"'t hold every key on the card"* && $out == *"Couldn'"'"'t get"* ]] && ! $real_gpg --list-keys "$other" >/dev/null 2>&1' "a URL with the wrong key imports nothing: $out"
echo 'http\x3a//127.0.0.1\x3a8765/key.asc' >"$T/url"
out=$(tty_run "$script" gpg status 2>&1)
check '[[ $out == *"Holder:      Card Owner"* && $out == *"http://127.0.0.1:8765/key.asc"* && $out == *"import it"* ]]' "gpg status reads the card: $out"
out=$(tty_run "$script" gpg import 2>&1)
check '$real_gpg --list-keys --with-colons "$fpr" | grep -q "^pub:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:u:"' "import brings the key in and trusts it: $out"
check '[[ $(git config --global user.signingkey) == "$fpr" && $(git config --global commit.gpgsign) == true ]]' "git signs with it"
check '! ls $XDG_RUNTIME_DIR/yubikey-gpg.* >/dev/null 2>&1' "the staging keyring is gone"
out=$(tty_run "$script" gpg status 2>&1)
check '[[ $out == *"ultimately trusted"* ]]' "status sees it trusted: $out"
gpg --homedir "$src" --batch --armor --export-secret-keys "$fpr" 2>/dev/null | $real_gpg --batch --import >/dev/null 2>&1
out=$(tty_run "$script" gpg remove 2>&1)
check '[[ $out == *"on disk"* ]] && $real_gpg --list-keys "$fpr" >/dev/null 2>&1' "remove refused with the secret on disk: $out"
$real_gpg --batch --yes --delete-secret-keys "$fpr" >/dev/null 2>&1
out=$(tty_run "$script" gpg remove 2>&1)
check '! $real_gpg --list-keys "$fpr" >/dev/null 2>&1' "remove takes the key out: $out"
kill $server

# The recipes reach the script.
out=$(just --justfile "$justfile" --list 2>&1)
check '[[ $out == *yubikey-u2f* && $out == *yubikey-gpg* && $out == *yubikey-ssh* ]]' "ujust lists the recipes"
out=$(just --justfile "$justfile" yubikey-ssh status 2>&1)
check '[[ $out == *"Resident SSH keys"* ]]' "ujust yubikey-ssh status runs the script: $out"

out=$("$script" nope 2>&1); rc=$?
check '[[ $rc == 2 && $out == *"usage: yubikey-manage u2f"* ]]' "usage on a wrong section"
out=$("$script" u2f register 2>&1 </dev/null); rc=$?
check '[[ $rc != 0 && $out == *"interactive terminal"* ]]' "actions need a terminal"

echo "$fails failure(s)"
exit $((fails > 0))
