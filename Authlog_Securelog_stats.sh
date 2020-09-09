#!/usr/bin/bash
# 09/09/2020
# Logs stats by Josue Martins
# Please run the script in the following way to suppress unecessary outputs.
# sh Authlog_Securelog_stats.sh ~/. 2>/dev/null


################################# AUTHLOGS ################################################

#Displaying, which logs files the script is reading data from.
echo "#################################################################";
echo "--> Reading from the following Authlogs files <--";
echo "Size	Name of the file";
find . -name 'authlog' ;

#finding this logs with successfull attempts
find . -name 'authlog' | xargs cat | egrep 'Accepted[[:blank:]]keyboard-interactive/pam[[:blank:]]for | Accepted[[:blank:]]publickey[[:blank:]]for' >> "sample.txt" ;
cat "sample.txt" >> "sample2.txt"; 

#finding logs with failed attempts
find . -name 'authlog' | xargs cat | egrep 'Failed[[:blank:]]none[[:blank:]]for' | egrep -i -v 'illegal|invalid' >> "sample3.txt" ; 
cat "sample3.txt" >> "sample4.txt";

#finding logs with failed attempts by illegal user.
find . -name 'authlog' | xargs cat | egrep 'Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal'| egrep -i -v 'Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal[[:blank:]]user[[:blank:]]ssh|Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal[[:blank:]]user[[:blank:]]telnet|Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal[[:blank:]]user[[:blank:]][[:blank:]]from[[:blank:]]'>> "illegal.txt";
cat "illegal.txt" >> "illegal2.txt";

#Jul 23 22:16:03 bear sshd[27716]: Failed none for illegal user telnet 172.19.1.20 from 10.22.135.166 port 3003 ssh2
find . -name 'authlog' | xargs cat | egrep 'Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal[[:blank:]]user[[:blank:]]ssh|Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal[[:blank:]]user[[:blank:]]telnet'| egrep -i -v 'Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal[[:blank:]]user[[:blank:]][[:blank:]]from[[:blank:]] && Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal[[:blank:]]user[[:blank:]]ssh|Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal[[:blank:]]user[[:blank:]]telnet[[:blank:]][[a-z][A-Z][0-9]]'>> "illegaluser.txt";


#Apr 26 14:35:33 bear sshd[1576]: Failed none for illegal user  from 
#finding users with double space infront of them.
find . -name 'authlog' | xargs cat | egrep 'Failed[[:blank:]]none[[:blank:]]for[[:blank:]]illegal[[:blank:]]user[[:blank:]][[:blank:]]from[[:blank:]]'>> "illegalfrom.txt";


#findling logs with Invalid users and grepping dead hours for them.
find . -name 'authlog' | xargs cat | egrep 'Invalid[[:blank:]]user[[:blank:]]' >> "invalid.txt" ; 
cat "invalid.txt" >> "invalid2.txt"; 
sed -i -e 's/Binary file (standard input) matches//g' "*.txt";


echo "#################################################################";

########################### User stats #######################################";
#this code shows the stats of users attempts
#Total successful attempts by users
awk 'BEGIN {									
print "**User**\t**IP**\t**Total successful attempts by users** \t";

}
{
User[$9"\t\t"$11]++; 
count[$9"\t"$11]+=$NF;

}
END{
for (var in User)
	if (length(var) > 2)
		print var,"\t\t -------> ",User[var];
	
}
' "sample2.txt" | sort -k1;
echo "#################################################################";

#Total failed attempts by users
awk 'BEGIN {									
print "**User**\t**IP**\t**Total failed attempts by users** \t";

}
{
User[$9 "\t\t"$11]++; 
count[$9 "\t" $11]+=$NF;

}
END{
for (var in User)
	if (length(var) > 1)
		print var,"\t\t -------> ",User[var];
	
}
' "sample3.txt" | sort -k1;
echo "#################################################################";


awk 'BEGIN {									
print "**Users**\t\t**IP **\t\t\t**Total failed attempts by IPs via illegal users** \t";

}
{
User[$11"\t\t"$13]++;
count[$13]+=$NF;



}
END{
for (var in User)
	if ((length(var) > 1)&&(length(var) > 4))	
		print var,"\t\t -------> ",User[var];
	
}
' "illegal2.txt" | sort -k1;
echo "##################################################################";


sed -i -e 's/Binary file (standard input) matches//g' "invalid2.txt";


#Total failed attempts by ip from invalid users.
awk 'BEGIN {									
print "**User**\t**IP**\t\t\t**Total failed attempts by ip from invalid users** \t";

}
{
User[$8"       \t"$10]++;
count[$10]+=$NF;

}
END{
for (var in User)
	if ((length(var) > 2) || (length(var) != 0 ))
		print var,"\t ------->\t",User[var];
	
	
}
' "invalid2.txt" | sort -k1;


########################### IP stats #######################################";

echo "##################################################################";


awk 'BEGIN {									
print "**IP ** \t**Total successful attempts by IPs** \t";

}
{
IPs[$11]++;
count[$11]+=$NF;

}
END{
for (var in IPs)
	if (length(var) != 0)
	print var,"\t\t -------> ",IPs[var];
	
}
' "sample2.txt"| sort -k1;

echo "#################################################################";

#Total failed attempts by IPs
awk 'BEGIN {									
print "**IP ** \t**Total failed attempts by IPs** \t";

}
{
IPs[$11]++;
count[$11]+=$NF;

}
END{
for (var in IPs)
		if (length(var) != 0)
		print var,"\t\t -------> ",IPs[var];
	
}
' "sample3.txt"| sort -k1;
echo "#################################################################";

#Total failed attempts by IPs via illegal users.
awk 'BEGIN {									
print "**IP ** \t**Total failed attempts by IPs via illegal users** \t";

}
{
IPs[$13]++;
count[$13]+=$NF;



}
END{
for (var in IPs)
	if ((length(var) != 0)&&(length(var) != 4))	
	print var,"\t\t -------> ",IPs[var];
	
}
' "illegal2.txt"| sort -k1;
echo "##################################################################";

#Total failed attempts by ip from invalid users.
awk 'BEGIN {									
print "**IP ** \t**Total failed attempts by ip from invalid users** \t";

}
{
IPs[$10]++;
count[$10]+=$NF;

}
END{
for (var in IPs)
	if (length(var) != 0)
	print var,"\t\t -------> ",IPs[var];
	
}
' "invalid2.txt"| sort -k1;

echo "#################################################################";


rm "sample.txt";
rm "sample2.txt";
rm "sample3.txt";
rm "sample4.txt";
rm "illegal.txt";
rm "illegal2.txt";
rm "illegaluser.txt";
rm "illegalfrom.txt";
rm "invalid.txt";
rm "invalid2.txt";

############################### THE END FOR AUTHLOGS###################################


################################# SECURE LOGS ################################################



#Displaying, which logs files the script is reading data from:
echo " --> Reading from the following Secure logs files <--";
echo "Size	Name of the file";
find . -name 'secure*' ; 

#finding this logs with successfull attempts Aug  9 06:08:35 proxy-au15 sshd[26700]: Accepted keyboard-interactive/pam for admin from 10.11.138.14 port 49529 ssh2

find . -name 'secure*' | xargs cat | egrep 'Accepted[[:blank:]]password[[:blank:]]for | Accepted[[:blank:]]keyboard-interactive/pam[[:blank:]]for'  >> "sec1.txt" ;


#finding logs with failed attempts - Failed password for mtoc from 192.168.195.27 port 47143 ssh2
find . -name 'secure*' | xargs cat | egrep 'Failed[[:blank:]]password[[:blank:]]for ' | egrep -i -v 'illegal|invalid' >> "sec2.txt" ; 


find . -name 'secure*' | xargs cat | egrep 'Failed[[:blank:]]password[[:blank:]]for[[:blank:]]invalid[[:blank:]]user'  >> "sec3.txt" ; 


sed -i -e 's/Binary file (standard input) matches//g' "*.txt";


echo "#################################################################";
#this code shows the stats of users attempts
#Total successful attempts by users
awk 'BEGIN {									
print "**User**\t**IP**\t**Total successful attempts by users** \t";

}
{
User[$9"\t\t"$11]++; 
count[$9"\t"$11]+=$NF;

}
END{
for (var in User)
	if (length(var) > 2)
		print var,"\t\t -------> ",User[var];
	
}
' "sec1.txt" | sort -k1;
echo "#################################################################";

#Total failed attempts by users
awk 'BEGIN {									
print "**User**\t**IP**\t**Total failed attempts by users** \t";

}
{
User[$9 "\t\t"$11]++; 
count[$9 "\t" $11]+=$NF;

}
END{
for (var in User)
	if (length(var) >2)
		print var,"\t\t -------> ",User[var];
	
}
' "sec2.txt" | sort -k1;
echo "#################################################################";





#Total failed attempts by ip from invalid users.
awk 'BEGIN {									
print "**User**\t**IP**\t\t\t**Total failed attempts by ip from invalid users** \t";

}
{
IPs[$11"       \t"$13]++;
count[$13]+=$NF;

}
END{
for (var in IPs)
	if (length(var) !=0)
		print var,"\t ------->\t",IPs[var];
	
	
}
' "sec3.txt" | sort -k1;

#echo "#################################################################";


########################### IP stats for Secure logs #######################################";

echo "##################################################################";


awk 'BEGIN {									
print "**IP ** \t**Total successful attempts by IPs** \t";

}
{
IPs[$11]++;
count[$11]+=$NF;

}
END{
for (var in IPs)
	if (length(var) != 0)
	print var,"\t\t -------> ",IPs[var];
	
}
' "sec1.txt"| sort -k1;

echo "#################################################################";

#Total failed attempts by IPs
awk 'BEGIN {									
print "**IP ** \t**Total failed attempts by IPs** \t";

}
{
IPs[$11]++;
count[$11]+=$NF;

}
END{
for (var in IPs)
		if (length(var) != 0)
		print var,"\t\t -------> ",IPs[var];
	
}
' "sec2.txt"| sort -k1;
echo "#################################################################";

#Total failed attempts by IPs via illegal users.
awk 'BEGIN {									
print "**IP ** \t**Total failed attempts by IPs via illegal or invalid users** \t";

}
{
IPs[$13]++;
count[$13]+=$NF;



}
END{
for (var in IPs)
	if ((length(var) != 0)&&(length(var) != 4))	
	print var,"\t\t -------> ",IPs[var];
	
}
' "sec3.txt"| sort -k1;
echo "############################# THE END #####################################";



#Temporary files must be removed
rm "sec1.txt";
rm "sec2.txt";
rm "sec3.txt";


############################### THE END###################################


