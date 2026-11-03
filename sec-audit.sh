#!/bin/bash
# sec-audit.sh - daily host security audit (CND Assessment 2)
# Author  : 0xOPFP
# Usage   : sec-audit.sh [-h] [-d] [-v] [-f URL] [-S PATH] [-A PATH]
# Exit    : 0 ok, 1 usage error, 3 bad signature (A3),
#           66 baseline checksum mismatch (A4)
# Runs as root from the system crontab; no sudo inside
# Version : final, 03/11/2026

set -u # strict: unset variable = stop

# ==== Functions: used many times below (General consideration) ====
# step: -v diagnostic line with the item code
step() {
  if [ "$VERBOSE" = "yes" ]; then
    echo "$1" >&2
  fi
}

# warn: warning on stderr, the script continues; counted
warn() {
  echo "WARNING: $1" >&2
  WARNINGS=$((WARNINGS + 1))
}

# finish: E2 END line + clean-up; the trap runs it on EVERY exit
finish() {
  RC=$? # the exit code the script is leaving with
  if [ "$LOGOK" = "yes" ]; then # E1 found the log writable
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] END exit=$RC" >> "$LOG"
  else
    warn "E2 cannot write END line - log not writable"
  fi
  cd / # step out of the work directory before deleting it
  if [ -n "$WORK" ]; then # only if A1 created it
    rm -rf "$WORK"
  fi
}

# ==== CLI defaults (changed by the options below) ====
WARNINGS=0 # counted by warn, shown at the end
WORK="" # work directory, made in A1
DRY="no" # -d  only /tmp may be written
VERBOSE="no" # -v  step names to stderr
FEED="" # -f  feed base URL (no default)
AUTHLOG="/var/log/auth.log" # -S  ssh log to analyse (B)
ACCESSLOG="/var/log/apache2/access.log" # -A  web log (A5)
BASE="/var/lib/sec-audit" # baseline files, 0700
RUN="/var/run/secdaily" # today's files, 0750
LOG="/var/log/secaudit.log" # script log (E1-E3)
LOGOK="yes" # E1 sets no if the log is unwritable
MASTER="config-master.dragur.no" # E4 rsync target
PORT="8753" # E4 ssh port
USAGE="Usage: $0 [-h] [-d] [-v] [-f URL] [-S PATH] [-A PATH]"

# ==== CLI parsing: position independent (getopts) ====
while getopts "hdvf:S:A:" opt; do
  case $opt in
    h) echo "$USAGE"
       echo " -h Show help"
       echo " -d Dry run (temporary files only)"
       echo " -v Verbose/descriptive mode to stderr"
       echo " -f URL Threat Intelligence URL feed"
       echo " -S PATH Authentication log for testing"
       echo " -A PATH Access log for testing"
       exit 0 ;;
    d) DRY="yes" ;;
    v) VERBOSE="yes" ;;
    f) FEED="$OPTARG" ;;
    S) AUTHLOG="$OPTARG" ;;
    A) ACCESSLOG="$OPTARG" ;;
    *) echo "$USAGE" >&2 # Default fallback if other values
       exit 1 ;;
  esac
done

# ==== CLI dry run (-d): nothing outside /tmp may change ====
if [ "$DRY" = "yes" ]; then
  RUN="/tmp/secdaily"
  LOG="/tmp/secaudit.log"
fi

# ==== CLI verbose (-v): display settings on stderr ====
if [ "$VERBOSE" = "yes" ]; then
  echo "CLI dry=$DRY feed=$FEED" >&2
  echo "CLI auth=$AUTHLOG access=$ACCESSLOG" >&2
  echo "CLI base=$BASE run=$RUN log=$LOG" >&2
fi

# ==== E3 log rotation: rotate when the log is above 100 KB ====
step "E3 log rotation"
if [ -f "$LOG" ]; then
  SIZE=$(stat -c %s "$LOG")
  if [ "$SIZE" -gt 102400 ]; then
    mv "$LOG" "$LOG-$(date +%Y%m%d)"
  fi
fi

# ==== E1 log start: date, options and user to the log ====
step "E1 log start"
touch "$LOG" 2>/dev/null
if [ ! -w "$LOG" ]; then
  warn "E1 cannot write $LOG - logging disabled for this run"
  LOGOK="no"
fi
NOW=$(date '+%Y-%m-%d %H:%M:%S')
if [ "$LOGOK" = "yes" ]; then
  echo "[$NOW] START $0 $* user=$(whoami)" >> "$LOG"
fi
trap finish EXIT # E2: run finish on every exit from here
# Report start (Task definition: feedback while the script runs)
echo "Security audit report: $(hostname) $NOW"

# ==== A1 fetch: rules package, verify file and their signatures ====
step "A1 fetch feed"
HOST=$(echo -n "$(hostname)" | md5sum | cut -d ' ' -f 1)
WORK=$(mktemp -d /tmp/secaudit.XXXXXX) # XXXXXX = random values
RULES="daily-rules.tar.gz"
VERIFY="$HOST-verify.tar.gz"
FEEDOK="yes"
if [ -z "$FEED" ]; then
  warn "A1 no feed URL given (-f) - threat checks skipped"
  FEEDOK="no"
else
  for FILE in "$RULES" "$RULES.gpg" "$VERIFY" "$VERIFY.gpg"; do
    if ! curl -s -f -o "$WORK/$FILE" "$FEED/$FILE"; then
      warn "A1 cannot fetch $FEED/$FILE"
      FEEDOK="no"
    fi
  done
fi
if [ "$FEEDOK" = "yes" ]; then
  echo "A1 feed: 4 files fetched from $FEED"
fi

# ==== A2 verify: check both archives against their signatures ====
step "A2 verify signatures"
SIGOK="no"
if [ "$FEEDOK" = "yes" ]; then
  if [ ! -d "$BASE/keys" ]; then
    warn "A2 $BASE/keys is missing - cannot verify"
  fi
  mkdir -m 700 "$WORK/gnupg"
  gpg --homedir "$WORK/gnupg" --import "$BASE"/keys/* >/dev/null 2>&1
  cd "$WORK"
  SIGOK="yes"
  gpg --homedir gnupg --verify "$RULES.gpg" "$RULES" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    SIGOK="no"
  fi
  gpg --homedir gnupg --verify "$VERIFY.gpg" "$VERIFY" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    SIGOK="no"
  fi
  if [ "$SIGOK" = "yes" ]; then
    echo "A2 signatures: both archives verified"
  fi
fi

# ==== A3 bad signature: syslog, quarantine, message, exit 3 ====
if [ "$FEEDOK" = "yes" ] && [ "$SIGOK" = "no" ]; then
  echo "A3 ERROR: feed signature failed - exit 3"
  if [ "$DRY" = "yes" ]; then
    echo "A3 dry run: syslog alert not sent, files not quarantined"
  else
    logger -p local0.emerg "sec-audit: bad feed signature $(hostname)"
    if ! mv "$WORK"/*.tar.gz* "$BASE/quarantine/" 2>/dev/null; then
      warn "A3 cannot move files to $BASE/quarantine"
    fi
  fi
  exit 3
fi

# ==== A4 baseline check: sha256 sums from the verify archive ====
step "A4 baseline check"
if [ "$SIGOK" = "yes" ]; then
  mkdir "$WORK/verify"
  tar xzf "$WORK/$VERIFY" -C "$WORK/verify" 2>/dev/null
  LIST=$(find "$WORK/verify" -type f | head -n 1)
  if [ -z "$LIST" ]; then
    warn "A4 verify archive holds no file - skipped"
  elif [ ! -d "$BASE" ]; then
    warn "A4 $BASE is missing - cannot check"
  else
    date -d yesterday +%Y%m%d > "$WORK/dates.txt"
    date -d yesterday +%Y-%m-%d >> "$WORK/dates.txt"
    date +%Y%m%d >> "$WORK/dates.txt"
    date +%Y-%m-%d >> "$WORK/dates.txt"
    if ! head -n 1 "$LIST" | grep -q -f "$WORK/dates.txt"; then
      warn "A4 verify data is stale (not from today or yesterday)"
    fi
    cd "$BASE"
    sha256sum -c "$LIST" > "$WORK/a4out.txt" 2>/dev/null
    RC=$?
    grep -v "OK$" "$WORK/a4out.txt" > "$WORK/a4bad.txt"
    if [ "$RC" -ne 0 ] || [ -s "$WORK/a4bad.txt" ]; then
      echo "A4 ERROR: baseline check failed - exit 66"
      cat "$WORK/a4bad.txt"
      exit 66
    fi
    echo "A4 baseline: all files match"
  fi
fi

# ==== A5 rules: unpack the verified daily rules archive ====
step "A5 threat rules"
THREATIP_LIST="$WORK/threatip.txt"
BADHASH_LIST="$WORK/badhash.txt"
HITS_FILE="$WORK/hits.txt"
if [ "$SIGOK" = "yes" ]; then
  mkdir "$WORK/rules"
  tar xzf "$WORK/$RULES" -C "$WORK/rules" 2>/dev/null
  cd "$WORK/rules"
  if [ ! -f THREATIP ] || [ ! -f BADHASH ]; then
    warn "A5 rules archive is incomplete"
  fi
  awk -F '#' '{print $1}' THREATIP | tr -d ' \t\r' > "$WORK/tip1.txt"
  grep -v '^$' "$WORK/tip1.txt" > "$THREATIP_LIST"
  awk -F '#' '{print $1}' BADHASH | tr -d ' \t\r' > "$WORK/bad1.txt"
  grep -v '^$' "$WORK/bad1.txt" > "$BADHASH_LIST"
else
  warn "A5 no verified rules - checks skipped"
fi

# ==== A5 THREATIP: threat IPs in the last 48 h of logs ====
if [ -s "$THREATIP_LIST" ]; then
  find /var/log -type f -mtime -2 > "$WORK/logs.txt" 2>/dev/null
  if [ -f "$ACCESSLOG" ]; then
    echo "$ACCESSLOG" >> "$WORK/logs.txt"
  else
    warn "A5 access log $ACCESSLOG not found"
  fi
  for LOGF in $(sort -u "$WORK/logs.txt"); do
    zgrep -H -n -w -F -f "$THREATIP_LIST" "$LOGF" 2>/dev/null \
      >> "$HITS_FILE"
  done
  if [ -s "$HITS_FILE" ]; then
    echo "A5 ALERT: threat IPs found in logs (file:line:text)"
    cat "$HITS_FILE"
  else
    echo "A5 THREATIP: no matches in the logs"
  fi
fi

# ==== A5 BADHASH: known-bad hashes among the system binaries ====
if [ -s "$BADHASH_LIST" ]; then
  BINS="/bin /sbin /usr/bin /usr/sbin"
  find $BINS -type f -exec sha256sum {} \; > "$WORK/hashes.txt"
  grep -w -F -f "$BADHASH_LIST" "$WORK/hashes.txt" > "$WORK/a5bad.txt"
  if [ ! -s "$WORK/a5bad.txt" ]; then
    echo "A5 BADHASH: no matches among the binaries"
  fi
  while read -r HASH FILE; do
    echo "A5 ALERT: bad hash $FILE sha256=$HASH"
    stat -c '  owner=%U:%G perms=%a created=%w modified=%y' "$FILE"
    if [ "$DRY" = "yes" ]; then
      echo "  dry run: $FILE not quarantined"
    else
      QF="$BASE/quarantine/$HASH"
      if cp "$FILE" "$QF" 2>/dev/null && chown root:root "$QF" \
         && chmod 400 "$QF"; then
        chmod 000 "$FILE"
        chown root:root "$FILE"
        echo "  quarantined as $QF; original: mode 000, owner root"
      else
        warn "A5 cannot quarantine $FILE - original left unchanged"
      fi
    fi
  done < "$WORK/a5bad.txt"
fi

# ==== B1 auth.log: collect the failed ssh logins ====
step "B1 parse auth.log"
cd "$WORK"
if [ -r "$AUTHLOG" ]; then
  grep "sshd" "$AUTHLOG" | grep "Failed" > failed.txt
else
  warn "B1 cannot read $AUTHLOG - no ssh statistics"
  touch failed.txt # empty: every B count below is 0
fi

# ==== B2 failed logins: total and the top 10 invalid user names ====
step "B2 failed logins"
TOTAL=$(wc -l < failed.txt)
echo "B2 failed ssh logins: $TOTAL"
echo "B2 top 10 invalid user names (count name):"
grep "invalid user" failed.txt > inv.txt
awk -F 'invalid user ' '{print $2}' inv.txt > inv2.txt
awk '{print $1}' inv2.txt | sort | uniq -c | sort -rn | head -n 10

# ==== B3 source IPs: failing addresses with their counts ====
step "B3 source IPs"
grep " from " failed.txt > from.txt
awk -F ' from ' '{print $2}' from.txt > from2.txt
awk '{print $1}' from2.txt | sort | uniq -c | sort -rn > counts.txt
awk '{printf "%-20s%s\n", $2, $1}' counts.txt > ips.txt
N=$(wc -l < ips.txt)
echo "B3 failing source IPs: $N (IP count)"
cat ips.txt

# ==== B4 sships.today: write IP and count atomically ====
step "B4 write sships.today"
mkdir -p "$RUN" 2>/dev/null
chmod 750 "$RUN" 2>/dev/null
TMP="$RUN/sships.today.$$"
if cp ips.txt "$TMP" 2>/dev/null; then
  mv "$TMP" "$RUN/sships.today"
  echo "B4 sships.today written to $RUN"
else
  warn "B4 cannot write $RUN/sships.today"
fi

# ==== B5 compare: today's top 20 against sships.yesterday ====
step "B5 compare with yesterday"
head -n 20 ips.txt | awk '{print $1}' | sort > top20.txt
YESTERDAY_FILE="$BASE/sships.yesterday"
touch yips.txt
if [ -r "$YESTERDAY_FILE" ]; then
  awk '{print $1}' "$YESTERDAY_FILE" | grep -v '^$' | sort > yips.txt
else
  warn "B5 cannot read $YESTERDAY_FILE - no comparison"
fi
comm -12 top20.txt yips.txt > repeat.txt
N=$(wc -l < repeat.txt)
echo "B5 repeat offenders (today's top 20 also seen yesterday): $N"
cat repeat.txt

# ==== B6 report: top 10 as "IP - N attempts [REPEAT]" ====
step "B6 top 10 report"
echo "B6 top 10 failing source IPs (and repeats from the top 20):"
head -n 10 ips.txt > top10.txt
while read -r IP COUNT; do
  TAG=""
  if grep -q -x -F "$IP" repeat.txt; then
    TAG=" [REPEAT]"
  fi
  echo "$IP - $COUNT attempts$TAG"
done < top10.txt
awk 'NR > 10' ips.txt | head -n 10 > rank11.txt
grep -w -F -f repeat.txt rank11.txt > more.txt
awk '{print $1 " - " $2 " attempts [REPEAT]"}' more.txt

# ==== B7 root ssh keys: keys without execution restrictions ====
step "B7 root ssh keys"
KEYS="/root/.ssh/authorized_keys"
if [ -r "$KEYS" ]; then
  grep -v '^#' "$KEYS" | grep -v '^$' > rootkeys.txt
  grep -v 'command=' rootkeys.txt > open.txt
  N=$(wc -l < open.txt)
  echo "B7 root ssh keys without execution restrictions: $N"
  awk '{print "  key type " $1 " comment " $NF}' open.txt
else
  echo "B7 $KEYS not present or not readable - nothing to check"
fi

# ==== C1 interfaces: physical interfaces, state and addresses ====
step "C1 interfaces"
echo "C1 physical interfaces (name state addresses):"
for IFDIR in /sys/class/net/*; do
  IFACE=$(basename "$IFDIR")
  if [ -e "$IFDIR/device" ]; then   # a driver behind it = physical
    ip -br addr show "$IFACE"
  fi
done

# ==== C2 established: TCP connections per local port ====
step "C2 established connections"
echo "C2 established TCP connections per local port (count port):"
ss -tnH | grep "ESTAB" | awk '{print $4}' > estab.txt
awk -F: '{print $NF}' estab.txt | sort | uniq -c | sort -rn

# ==== C3 listening: ports v4/v6 against ports.allowed ====
step "C3 listening ports"
ss -tulnH | awk '{print $5 "/" $1}' > ports.txt
awk -F: '{print $NF}' ports.txt | sort -u > listen.txt
echo "C3 listening ports (port/protocol):"
cat listen.txt
PORTS_FILE="$BASE/ports.allowed"
PORTDIFF="no"
if [ -r "$PORTS_FILE" ]; then
  grep -v '^#' "$PORTS_FILE" | grep -v '^$' | sort -u > allowed.txt
  grep -v -x -F -f allowed.txt listen.txt > notallowed.txt
  grep -v -x -F -f listen.txt allowed.txt > notlisten.txt
  echo "C3 listening ports not in ports.allowed:"
  cat notallowed.txt
  echo "C3 allowed ports not listening:"
  cat notlisten.txt
  if [ -s notallowed.txt ] || [ -s notlisten.txt ]; then
    PORTDIFF="yes"
  fi
else
  warn "C3 cannot read $PORTS_FILE"
fi

# ==== C4 promiscuous: interfaces in promiscuous mode ====
step "C4 promiscuous mode"
if ip -br link | grep -q "PROMISC"; then
  echo "C4 ALERT: interface in promiscuous mode:"
  ip -br link | grep "PROMISC"
else
  echo "C4 promiscuous mode: none"
fi

# ==== C5 static ARP: permanent neighbour entries ====
step "C5 static ARP"
if ip neigh show | grep -q -i "PERMANENT"; then
  echo "C5 ALERT: static ARP entries found:"
  ip neigh show | grep -i "PERMANENT"
else
  echo "C5 static ARP entries: none"
fi

# ==== C6 gateway: default gateway MAC against gateway.allowed ====
step "C6 gateway MAC"
GW=$(ip route show default | awk '{print $3}' | head -n 1)
ping -c 1 -W 1 "$GW" >/dev/null 2>&1
GWMAC=$(ip neigh show "$GW" | grep lladdr | awk '{print $5}')
GATEWAY_FILE="$BASE/gateway.allowed"
MACDIFF="no"
if [ -z "$GWMAC" ]; then
  warn "C6 no default gateway MAC found"
elif [ ! -r "$GATEWAY_FILE" ]; then
  warn "C6 cannot read $GATEWAY_FILE"
elif grep -v '^#' "$GATEWAY_FILE" | grep -q -i -x "$GWMAC"; then
  echo "C6 default gateway $GW MAC $GWMAC: allowed"
else
  echo "C6 ALERT: gateway $GW MAC $GWMAC not in gateway.allowed"
  MACDIFF="yes"
fi

# ==== D1 SUID/SGID: locate the set-uid and set-gid binaries ====
step "D1 locate SUID and SGID files"
MOUNTS=$(findmnt -rn -o TARGET -t ext4,xfs,btrfs)
if [ -z "$MOUNTS" ]; then
  MOUNTS="/"
fi
for M in $MOUNTS; do
  find "$M" -xdev -perm -4000 -type f 2>/dev/null >> suid1.txt
  find "$M" -xdev -perm -2000 -type f 2>/dev/null >> guid1.txt
done
sort -u suid1.txt > suid.txt
sort -u guid1.txt > guid.txt

# ==== D2 today files: path, sha256 and user:group ====
step "D2 write suid.today and guid.today"
for F in $(cat suid.txt); do
  HASH=$(sha256sum "$F" | cut -d ' ' -f 1)
  OWNER=$(stat -c '%U:%G' "$F")
  echo "$F  $HASH $OWNER"
done > "$RUN/suid.today"
for F in $(cat guid.txt); do
  HASH=$(sha256sum "$F" | cut -d ' ' -f 1)
  OWNER=$(stat -c '%U:%G' "$F")
  echo "$F  $HASH $OWNER"
done > "$RUN/guid.today"
echo "D2 suid.today and guid.today written to $RUN"

# ==== D3 compare: today against suid.yesterday ====
# yesterday may hold paths only or "path hash owner"; a * needs a hash
step "D3 compare with yesterday"
YESTERDAY_FILE="$BASE/suid.yesterday"
echo "D3 SUID changes ([*] changed, [-] removed, [+] added):"
SUIDDIFF="no"
if [ ! -r "$YESTERDAY_FILE" ]; then
  warn "D3 cannot read $YESTERDAY_FILE"
else
  awk '{print $1}' "$YESTERDAY_FILE" | grep -v '^#' > ysuid.txt
  for F in $(cat suid.txt); do
    THASH=$(sha256sum "$F" | cut -d ' ' -f 1)
    YHASH=$(grep -F "$F " "$YESTERDAY_FILE" | awk '{print $2}')
    MTIME=$(stat -c '%y' "$F" | cut -c 1-19)
    PACKAGE=$(dpkg -S "$F" 2>/dev/null | cut -d : -f 1)
    if ! grep -q -x -F "$F" ysuid.txt; then
      echo "[$MTIME] [+] $F $THASH $PACKAGE"
      SUIDDIFF="yes"
    elif [ -n "$YHASH" ] && [ "$YHASH" != "$THASH" ]; then
      echo "[$MTIME] [*] $F $THASH $PACKAGE"
      SUIDDIFF="yes"
    fi
  done
  for F in $(cat ysuid.txt); do
    if ! grep -q -x -F "$F" suid.txt; then
      YHASH=$(grep -F "$F " "$YESTERDAY_FILE" | awk '{print $2}')
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] [-] $F $YHASH"
      SUIDDIFF="yes"
    fi
  done
fi

# ==== D3 compare: today against guid.yesterday ====
YESTERDAY_FILE="$BASE/guid.yesterday"
echo "D3 SGID changes ([*] changed, [-] removed, [+] added):"
GUIDDIFF="no"
if [ ! -r "$YESTERDAY_FILE" ]; then
  warn "D3 cannot read $YESTERDAY_FILE"
else
  awk '{print $1}' "$YESTERDAY_FILE" | grep -v '^#' > yguid.txt
  for F in $(cat guid.txt); do
    THASH=$(sha256sum "$F" | cut -d ' ' -f 1)
    YHASH=$(grep -F "$F " "$YESTERDAY_FILE" | awk '{print $2}')
    MTIME=$(stat -c '%y' "$F" | cut -c 1-19)
    PACKAGE=$(dpkg -S "$F" 2>/dev/null | cut -d : -f 1)
    if ! grep -q -x -F "$F" yguid.txt; then
      echo "[$MTIME] [+] $F $THASH $PACKAGE"
      GUIDDIFF="yes"
    elif [ -n "$YHASH" ] && [ "$YHASH" != "$THASH" ]; then
      echo "[$MTIME] [*] $F $THASH $PACKAGE"
      GUIDDIFF="yes"
    fi
  done
  for F in $(cat yguid.txt); do
    if ! grep -q -x -F "$F" guid.txt; then
      YHASH=$(grep -F "$F " "$YESTERDAY_FILE" | awk '{print $2}')
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] [-] $F $YHASH"
      GUIDDIFF="yes"
    fi
  done
fi

# ==== D4 /etc/passwd: only root has UID 0, no duplicate UIDs ====
step "D4 check UIDs"
awk -F: '$3 == 0 {print $1}' /etc/passwd > uid0_users.txt
if grep -q -v -x "root" uid0_users.txt; then
  echo "D4 ALERT: UID 0 is not only root:"
  cat uid0_users.txt
else
  echo "D4 UID 0: only root"
fi
if ! grep -q -x "root" uid0_users.txt; then
  echo "D4 ALERT: root does not have UID 0"
fi
awk -F: '{print $3}' /etc/passwd | sort | uniq -d > dupuid.txt
if [ -s dupuid.txt ]; then
  echo "D4 ALERT: duplicate UIDs:"
  cat dupuid.txt
else
  echo "D4 duplicate UIDs: none"
fi

# ==== D5 /tmp: files older than 48 hours and their total size ====
step "D5 old files in /tmp"
find /tmp -type f -mmin +2880 2>/dev/null > old.txt
echo "D5 files in /tmp older than 48 hours (KB path):"
TOTAL=0
while read -r F; do
  KB=$(du -k "$F" | awk '{print $1}')
  echo "$KB $F"
  TOTAL=$((TOTAL + KB))
done < old.txt
echo "D5 total: $TOTAL KB"

# ==== E3 UPDATE: which checks found differences ====
step "E3 UPDATE file, checksums, archive and signature"
rm -f "$RUN/UPDATE"
if [ "$PORTDIFF" = "yes" ]; then
  echo "PORTS" >> "$RUN/UPDATE"
fi
if [ "$MACDIFF" = "yes" ]; then
  echo "MAC" >> "$RUN/UPDATE"
fi
if [ "$SUIDDIFF" = "yes" ]; then
  echo "SUID" >> "$RUN/UPDATE"
fi
if [ "$GUIDDIFF" = "yes" ]; then
  echo "GUID" >> "$RUN/UPDATE"
fi
if [ -f "$RUN/UPDATE" ]; then
  echo "E3 UPDATE written (differences found):"
  cat "$RUN/UPDATE"
else
  echo "E3 UPDATE: no differences, file not written"
fi

# ==== E3 checksums: sha256 of the files in /var/run/secdaily ====
DATE=$(date +%Y%m%d)
cd "$RUN"
rm -f "$DATE-secdaily.sha256" COMPLETE   # both are rewritten below
sha256sum * > "$DATE-secdaily.sha256"
cd "$WORK"
echo "E3 checksums: $DATE-secdaily.sha256 written to $RUN"

# ==== E3 archive: tar.gz of /var/run/secdaily and signature ====
TGZ="$HOST-$DATE.tgz"
tar czf "$TGZ" -C "$RUN" .
HOSTID_FILE="$BASE/keys/$HOST.id"
if [ ! -r "$HOSTID_FILE" ]; then
  HOSTID_FILE="$BASE/$HOST.id"
fi
if [ ! -r "$HOSTID_FILE" ]; then
  warn "E3 cannot find $HOST.id - archive not signed"
else
  KEYID=$(head -n 1 "$HOSTID_FILE" | awk '{print $NF}')
  gpg --batch --local-user "$KEYID" --detach-sign "$TGZ"
  if [ $? -ne 0 ]; then
    warn "E3 cannot sign $TGZ with key $KEYID"
  else
    echo "E3 archive: $TGZ signed with key $KEYID"
  fi
fi

# ==== E4 rsync: send the archive and signature to config-master ====
step "E4 rsync to $MASTER"
if [ ! -r "$HOSTID_FILE" ]; then
  warn "E4 no $HOST.id - archive not sent"
elif [ ! -f "$TGZ.sig" ]; then
  warn "E4 archive not signed - not sent"
elif [ "$DRY" = "yes" ]; then
  echo "E4 dry run: rsync to $MASTER skipped"
else
  USERID=$(head -n 2 "$HOSTID_FILE" | tail -n 1 | awk '{print $NF}')
  SSHKEY=$(head -n 3 "$HOSTID_FILE" | tail -n 1 | awk '{print $NF}')
  SSHCMD="ssh -p $PORT -i $SSHKEY -o BatchMode=yes"
  SSHCMD="$SSHCMD -o StrictHostKeyChecking=accept-new"
  DEST="$USERID@$MASTER:"
  if ! rsync -e "$SSHCMD" "$TGZ" "$TGZ.sig" "$DEST"; then
    warn "E4 rsync to $MASTER failed"
  else
    echo "E4 rsync: $TGZ and signature sent to $MASTER"
  fi
fi

# ==== E5 COMPLETE: datestamp, sha256 of the archive and hostname ====
step "E5 write COMPLETE"
ARCHASH=$(sha256sum "$TGZ" | cut -d ' ' -f 1)
NOW=$(date '+%Y-%m-%d %H:%M:%S')
echo "$NOW $ARCHASH $(hostname)" > "$RUN/COMPLETE"
echo "E5 COMPLETE written to $RUN"

# ==== E2 END: summary; the trap writes END and removes $WORK ====
step "E2 END"
echo "sec-audit finished: exit 0, warnings: $WARNINGS"
if [ "$DRY" = "yes" ]; then
  echo "dry run: results kept in $RUN and $LOG for inspection"
fi
exit 0
