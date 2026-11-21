# SentinelGlobe Zeek site policy
@load base/frameworks/notice
@load base/frameworks/notice/weird
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/http/detect-sql-injection
@load policy/protocols/conn/known-hosts
@load policy/protocols/ssl/validate-certs
@load policy/frameworks/files/hash-all-files

redef LogAscii::use_json = T;
redef Notice::emailed_types += {
  SSH::Password_Guessing,
  HTTP::SQL_Injection_Attacker,
};
redef Notice::ignored_types += {
  SSL::Invalid_Server_Cert,
};

event zeek_init() {
  print "SentinelGlobe Zeek sensor online";
}
