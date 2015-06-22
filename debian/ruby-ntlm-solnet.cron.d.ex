#
# Regular cron jobs for the ruby-ntlm-solnet package
#
0 4	* * *	root	[ -x /usr/bin/ruby-ntlm-solnet_maintenance ] && /usr/bin/ruby-ntlm-solnet_maintenance
