#!/bin/bash

#############################################################
#
#  ▪ Titulo: DnsKraken
#  ▪ Versao: 0.1
#  ▪ Data: 19/01/2021
#  ▪ Testado no: Kubuntu
#  ▪ Owner: vida
#  ▪ Contato: vidaᶜʸᵇᵉʳ#6443
#
#############################################################


#############################################################
# ▶ Cores
#############################################################
BLACK='\033[30;01;1m'
RED='\033[31;01;1m'
RED_BLINK='\033[31;01;05;1m'
CIANO='\033[36;01;1m'
CIANO_BLINK='\033[36;01;05;1m'
BLUE='\033[34;01;1m'
END='\033[m'

#############################################################
# ▶ Argumentos
#############################################################
op=$1			# op = opcao
#Pesquisa Direta
domain_direct=$2	# domain_direct = dominio do alvo
wd_direct=$4		# wd_direct = wordlist a ser usado
#Pesquisa Reversa
ip=$2			# ip = ip do alvo
rede=$4			# rede = rede do alvo
#Zone Transfer
domain_zone=$3		# domain_zone = dominio do alvo
#TakeOver
domain_take=$3		# domain_take = dominio do alvo
wd_take=$5		# wd_take = wordlist a ser usado
#############################################################

#############################################################
# ▶ Versao
#############################################################
versao='0.1'

#############################################################
# ▶ Ctrl+C
#############################################################
trap Ctrl_C INT
Ctrl_C(){
	echo -e "${RED_BLINK}\n[!] ACAO ABORTADA [!]${END}"
	exit 1
}
#############################################################
# ▶ Clear
#############################################################

Clear(){
	clear
}

#############################################################
# ▶ Banner
#############################################################
Banner(){
	Clear
	echo
	echo -e "${BLACK} ████████▄  ███▄▄▄▄      ▄████████         ▄█   ▄█▄    ▄████████    ▄████████    ▄█   ▄█▄    ▄████████ ███▄▄▄▄   ${END}"
	echo -e "${BLACK} ███   ▀███ ███▀▀▀██▄   ███    ███        ███ ▄███▀   ███    ███   ███    ███   ███ ▄███▀   ███    ███ ███▀▀▀██▄ ${END}"
	echo -e "${BLACK} ███    ███ ███   ███   ███    █▀         ███▐██▀     ███    ███   ███    ███   ███▐██▀     ███    █▀  ███   ███ ${END}"
	echo -e "${BLACK} ███    ███ ███   ███   ███              ▄█████▀     ▄███▄▄▄▄██▀   ███    ███  ▄█████▀     ▄███▄▄▄     ███   ███ ${END}"
	echo -e "${BLACK} ███    ███ ███   ███ ▀███████████      ▀▀█████▄    ▀▀███▀▀▀▀▀   ▀███████████ ▀▀█████▄    ▀▀███▀▀▀     ███   ███ ${END}"
	echo -e "${BLACK} ███    ███ ███   ███          ███        ███▐██▄   ▀███████████   ███    ███   ███▐██▄     ███    █▄  ███   ███ ${END}"
	echo -e "${CIANO} ███   ▄███ ███   ███    ▄█    ███        ███ ▀███▄   ███    ███   ███    ███   ███ ▀███▄   ███    ███ ███   ███ ${END}"
	echo -e "${CIANO} ████████▀   ▀█   █▀   ▄████████▀         ███   ▀█▀   ███    ███   ███    █▀    ███   ▀█▀   ██████████  ▀█   █▀  ${END}"
	echo -e "${CIANO}                                          ▀           ███    ███                ▀                                ${END}"
	echo -e "${CIANO}\t\t\t\t\t\t.:Coded By Vida:.${END}"
	echo
	echo -e "${CIANO} Welcome user, Have a nice experience${END}"
	echo -e "${CIANO} $0 -h ▶ para ver como usar o DnsKraken${END}"
	echo
}

#############################################################
# ▶ Help
#############################################################
Help(){
	echo
	echo -e "${CIANO}\t\t[SOS] Painel De Ajuda [SOS]\n${END}"
	echo -e "${BLUE} -v, --version    	Mostra a versao do programa${END}"
	echo -e "${BLUE} -h, --help       	Mostra o menu de ajuda${END}"
	echo -e "${BLUE} -z, --zonetransfer     Define que sera feito uma transferencia de zona${END}"
	echo -e "${BLUE} -t, --takeover		Define que sera feito um scan a procura de sub dominios vulneraveis a subdomain takeover${END}"
	echo -e "${BLUE} -d, --domain     	Define o dominio alvo(example.com APENAS)${END}"
	echo -e "${BLUE} -w, --wordlist   	Define a wordlist a ser usada no bruteforce${END}"
	echo -e "${BLUE} -i, --ip         	Define o ip alvo (Pesquisa Reversa)${END}"
	echo -e "${BLUE} -r, --rede       	Define a rede alvo${END}"
	echo
	echo -e "${CIANO}\t\t[?] EXEMPLOS [?]${END}"
	echo -e "${BLACK} ▶ Pesquisa Direta${END}"
	echo -e "${BLUE} $0 ${CIANO}-d${END}${BLUE} example.com -w wordlist.txt${END}"

	echo -e "${BLACK} ▶ Pesquisa Reverse${END}"
	echo -e "${BLUE} $0 ${CIANO}-i${END}${BLUE} 192.168.8.1 -r 192.168.8${END}"

	echo -e "${BLACK} ▶ Zone Transfer${END}"
	echo -e "${BLUE} $0 ${CIANO}-z${END}${BLUE} -d example.com${END}"

	echo -e "${BLACK} ▶ SubDomain - Take Over${END}"
	echo -e "${BLUE} $0 ${CIANO}-t${END}${BLUE} -d example.com -w wordlist.txt${END}"
	echo
	echo -e "${RED} [-] Se nao retornar nada e o script fechar -> Nada Encontrado${END}"
	echo -e "${RED} [-] Se nao estiver retornando nada mas o script continua em andamento -> Programa em andamento, aguarde!${END}"
	echo
}

#############################################################
# ▶ Verificacao
#############################################################
Verifica(){
	#Verifica as Dependencias
	if ! [[ -e /usr/bin/host ]];then
		echo "\n${BLUE}Dependencia: host${END}"
		echo "${CIANO}sudo apt install host${END}\n"
		exit 1
	elif ! [[ -e /usr/bin/whois ]];then
		echo -e "\n${BLUE}Dependencia: whois${END}"
		echo -e "${CIANO}sudo apt install whois${END}\n"
		exit 1
	fi

	#Verifica os argumentos
	if [ -z "$op" ];then
		Banner
		exit 1
	fi
}
#############################################################
# ▶ Verifica Opcoes
#############################################################
Verifica_Opcoes_Direct(){
	if [ -z "$domain_direct" ];then Help;exit 1;fi
	if [ -z "$wd_direct" ];then Help;exit 1;fi
	if [ ! -s "$wd_direct" ];then echo -e "${BLACK}Wordlist Inexistente${END}";exit 1;fi
}
Verifica_Opcoes_Reverse(){
	if [ -z "$ip" ];then Help;exit 1;fi
	if [ -z "$rede" ];then Help;exit 1;fi
}
Verifica_Opcoes_Zone(){
	if [ -z "$domain_zone" ];then Help;exit 1;fi
}
Verifica_Opcoes_Take(){
	if [ -z "$domain_take" ];then Help;exit 1;fi
	if [ -z "$wd_take" ];then Help;exit 1;fi
	if [ ! -s "$wd_take" ];then echo -e "${BLACK}Wordlist Inexistente${END}";exit 1;fi
}

#############################################################
# ▶ Verificacao do host
#############################################################
Verifica_Host_Direct(){
	verifica=$(host $domain_direct 2>/dev/null| cut -d "(" -f2 | sed 's/.$//')
	if [ "$verifica" == "NXDOMAIN" ] && [ "$verifica" == "SERVFAIL" ];then
		echo -e "${RED_BLINK}\n[-] HOST INDISPONIVEL [-]\n ${END}"
		exit 1

	fi
}
Verifica_Host_Zone(){
	verifica=$(host $domain_zone 2>/dev/null| cut -d "(" -f2 | sed 's/.$//')
	if [ "$verifica" == "NXDOMAIN" ] && [ "$verifica" == "SERVFAIL" ];then
		echo -e "${RED_BLINK}\n[-] HOST INDISPONIVEL [-]\n ${END}"
		exit 1
	fi
}
Verifica_Host_Take(){
	verifica=$(host $domain_take 2>/dev/null| cut -d "(" -f2 | sed 's/.$//')
	if [ "$verifica" == "NXDOMAIN" ] && [ "$verifica" == "SERVFAIL" ];then
		echo -e "${RED_BLINK}\n[-] HOST INDISPONIVEL\n [-]${END}"
		exit 1
	fi
}
Verifica_Host_IP(){
	verifica=$(host $ip 2>/dev/null| cut -d "(" -f2 | sed 's/.$//')
	if [ "$verifica" == "NXDOMAIN" ] && [ "$verifica" == "SERVFAIL" ];then
		echo -e "${RED_BLINK}\n[-] HOST INDISPONIVEL [-]\n ${END}"
		exit 1
	fi
}

#############################################################
# ▶ Get Range (Pesquisa Reversa)
#############################################################
Get_Range(){
        r1=$(whois $ip 2>/dev/null| grep "inetnum" | cut -d "." -f4 | cut -d " " -f1)
        r2=$(whois $ip 2>/dev/null| grep "inetnum" | cut -d "." -f7)
        for h in $(seq $r1 $r2);do echo -e "${BLACK}[+]Atacando: $rede.$h${END}" | tr '\n' '\r';host $rede.$h 2>/dev/null | egrep -v "SERVFAIL|NXDOMAIN" | grep -v "ip" | cut -d " " -f1,5 | cut -d "." -f1,2,3,4,6,7,8,9 | sed 's/arpa/ -> /';done; echo -e "\n${BLACK}--END--${END}"
}

#############################################################
# ▶ Get Subs (Pesquisa Direta)
#############################################################
Get_Sub(){
	for sub in $(cat $wd_direct);do
		echo -e "${BLACK}[+]Atacando: $domain_direct${END}" | tr '\n' '\r'
		host $sub.$domain_direct 2>/dev/null | egrep -v "NXDOMAIN|SERVFAIL" | cut -d " " -f1,4 | sed 's/ / -> /' | grep "$domain_direct" | grep -v "alias"
	done
	echo -e "\n${BLACK}--END--${END}"
}

#############################################################
# ▶ Get Subs Tk (Take Over)
#############################################################
Get_Tks(){
	for subs in $(cat $wd_take);do
		echo -e "${BLACK}[+]Atacando: $domain_take${END}\n" | tr '\n' '\r'
		sub_com_redirecionamento=$(host -t cname $subs.$domain_take 2>/dev/null | egrep -v "NXDOMAIN|SERVFAIL" | grep "alias for" | awk -F " " '{print $1}')
        	verifica_os_subs=$(host $sub_com_redirecionamento 2>/dev/null | awk -F " " '{print $5}' | cut -d "(" -f2 | cut -d ")" -f1)
 		if [ "$verifica_os_subs" == "NXDOMAIN" ];then
                        echo -e "${CIANO}[+] TakeOver: $verifica_os_subs  ${END}"
	        fi
	done
	echo -e "\n${BLACK}--END--${END}"
}

#############################################################
# ▶ Get Name Server (Zone Transfer)
#############################################################
Get_Ns(){
	for ns in $(host -t ns $domain_zone 2>/dev/null | awk -F " " '{print $4}');do echo -e "${BLACK}[+]Atacando: $domain_zone${END}" | tr '\n' '\r'; host -l -a $domain_zone $ns 2>/dev/null;done;echo -e "\n${BLACK}--END--${END}"
}

#############################################################
# ▶ SubDominios Findados Direct
#############################################################
Find_Direct(){
	echo
	echo -e "${CIANO}   __ ___ _  _ ___  ___  ${END}";
	echo -e "${CIANO}  / _|_ _| \| |   \/ __| ${END}";
	echo -e "${BLACK} |  _|| || .\` | |) \__\ ${END}";
	echo -e "${CIANO} |_| |___|_|\_|___/|___/ ${END}";
	echo

	echo -e "${BLACK}########################################${END}"
	echo -e "${CIANO}#    SUB DOMINIOS\t|\tIP     #${END}"
	echo -e "${BLACK}########################################${END}"
	echo
}

#############################################################
# ▶ SubDominios Findados Reverse
#############################################################
Find_Reverse(){
	echo
	echo -e "${CIANO}   __ ___ _  _ ___  ___  ${END}";
	echo -e "${CIANO}  / _|_ _| \| |   \/ __| ${END}";
	echo -e "${BLACK} |  _|| || .\` | |) \__\ ${END}";
	echo -e "${CIANO} |_| |___|_|\_|___/|___/ ${END}";
	echo

	echo -e "${BLACK}########################################${END}"
	echo -e "${CIANO}#   REVERSE IP\t|\tSUB DOMAIN     #${END}"
	echo -e "${BLACK}########################################${END}"
	echo
}

#############################################################
# ▶ SubDominos TakeOver Findados AND Zone Transfer Success
#############################################################
Find_TZ(){
	echo
	echo -e "${CIANO}   __ ___ _  _ ___  ___  ${END}";
	echo -e "${CIANO}  / _|_ _| \| |   \/ __| ${END}";
	echo -e "${BLACK} |  _|| || .\` | |) \__\ ${END}";
	echo -e "${CIANO} |_| |___|_|\_|___/|___/ ${END}";
	echo
}

#############################################################
# ▶ Funcao Main
#############################################################
Main(){
	Verifica
	case $op in
		"-v"|"--version")
			echo -e "\n${CIANO}Versao:${END}${BLACK} $versao${END}\n"
			exit 0
		;;
		"-h"|"--help")
			Help
			exit 0
		;;
		"-i"|"--ip")
			Verifica_Opcoes_Reverse
			Verifica_Host_IP
			Find_Reverse
			Get_Range
			exit 0
		;;
		"-d"|"--domain")
			Verifica_Opcoes_Direct
			Verifica_Host_Direct
			Find_Direct
			Get_Sub
			exit 0
		;;
		"-z"|"--zonetransfer")
			Verifica_Opcoes_Zone
			Verifica_Host_Zone
			Find_TZ
			Get_Ns
			exit 0
		;;
		"-t"|"--takeover")
			Verifica_Opcoes_Take
			Verifica_Host_Take
			Find_TZ
			Get_Tks
			exit 0
		;;
		*)
			Help
			exit 1
	esac
}

#############################################################
# ▶ Iniciando o Programa
#############################################################
Main
