#!/home/nate/.venv/modem/bin/python


v = "0.7" # Version number

#TODO:
#   - handle "No service" situation (gets stuck at check_connection_status function)
#       Currently the app gets stuck at "Switching on data connection..."
#   - add option to reboot modem? (not convinced about this one)

#Bugs:
#   - possible bug creating blank "1" file due to redirect in ping command
#   - not enough time given to determine if DNS is resolving after reconnecting data

#Feature Ideas:
#   - allow to check sms messages (read, mark as read, delete)
#   - find out when credit was last added?

import requests
import re
import hashlib
import base64
import datetime

from os import devnull
from os import system as shell              # Execute a shell command
from platform import system as system_name  # Returns the system/OS name
from sys import exit

from time import sleep
from time import localtime
from time import time
from time import strptime



# === Define functions ====================================================

def s_print(msg):
    er = '\r' + ' '*80 + '\r'
    print(er + msg, end='')


def print_app_info():
    print("\n=====================================================================")
    print("{0:^70s}".format("ModemCheck v" + v ))
    print("{0:^70s}".format("by Nate Marti, nate_marti@sil.org"))
    print("=====================================================================\n")


def get_language():
    link = api + 'language/current-language'
    label = get_value_from_page(link, 'CurrentLanguage')
    # English = en-us, French = fr-fr
    if label=="en-us":
        l = 0
    elif label=="fr-fr":
        l = 1
    else:
        s_print("Paramètre de langue inconnu. Le français a été choisi par défaut.")
        l = 1
    return l


def get_modem_ip():
    s_print("Determining modem IP address... | En train de chercher l'adresse IP de modem...")
    guess = "192.168.8.1"
    if ping_modem(guess, 1) is True:
        ip = guess
    else:
        guess = "192.168.100.1"
        if ping_modem(guess, 1) is True:
            ip = guess
        else:
            s_print('')
            input("Can't determine modem IP address. Press [Enter] to close. | Adresse IP de modem inconnue. Tappez [Enter] pour fermer.")
            exit(1)
    return ip

    
def ping_modem(host, pings):
    # Ping parameters as function of OS
    parameters = "-n " if system_name().lower()=="windows" else "-A -w1 -c "
    # Pinging
    result = shell("ping " + parameters + str(pings) + " " + host + ">" + devnull + " 2>&1") == 0
    return result


def ping_host(host, pings):
    # Ping parameters as function of OS
    parameters = "-n " if system_name().lower()=="windows" else "-A -w15 -c "
    # Pinging
    result = shell("ping " + parameters + str(pings) + " " + host + " >" + devnull + " 2>&1") == 0
    return result
    

def modem_check(modem_ip):
    # check for connection to modem
    s_print("Checking for modem... | En train de chercher le modem...")
    modem_ping = ping_host(modem_ip, 1)
    if modem_ping is not True:
        # no connection to modem
        # "No connection to modem. Exiting."
        s_print('')
        input("No connection to modem. Press [Enter] to exit. | Pas de connexion au modem. Tappez [Enter] pour fermer.")
        exit(1)


def grep_csrf(html):
    pat = re.compile(r".*meta name=\"csrf_token\" content=\"(.*)\"", re.I)
    matches = (pat.match(line) for line in html.splitlines())
    return [m.group(1) for m in matches if m]


def login_data(username, password, csrf_token):
    def encrypt(string):
        m = hashlib.sha256()
        m.update(string.encode('utf-8'))
        encrypted = base64.urlsafe_b64encode(m.hexdigest().encode('utf-8')).decode()
        return encrypted

    password_hash = encrypt(username + encrypt(password) + csrf_token)

    return {
        'Username': username,
        'Password': password_hash,
        'password_type': '4',
        }


def login(username, password, token):
    #TODO: Somehow, the data dictionary below doesn't work, but I still need the password hash from it.
    data = login_data(username, password, token)
    login_payload = '<?xml version="1.0" encoding="UTF-8"?>\
                        <request>\
                            <Username>' + data['Username'] + '</Username>\
                            <Password>' + data['Password'] + '</Password>\
                            <password_type>' + data['password_type'] + '</password_type>\
                        </request>'
    r = s.post(api + 'user/login', data=login_payload)
    try:
        s.headers.update({'__RequestVerificationToken': r.headers['__RequestVerificationTokenone']})
    except KeyError:
        # login failed
        s.headers.update({'__RequestVerificationToken': r.headers['__RequestVerificationToken']})
        state = check_login_state()
        return state
    s.headers.update({'Cookie': 'SessionID=' + r.cookies['SessionID']})
    state = check_login_state()
    return state


def modem_login():
    user = 'admin'
    pwds = ['admin', 'MyTlcl2017']
    for i in range(2):
        token = s.headers['__RequestVerificationToken']
        state = login(user, pwds.pop(0), token)
        if state == 0:
            return
        elif state == -1:
            continue
        else:
            # something went wrong
            s_print("Login failed. Exiting.")
            print()
            exit(1)
    # If default options didn't work, go to user input.
    for i in range(1):
        s_print('')
        user = input("username: ")
        print('\033[1A' + ' '*80 + '\r', end='')
        pwd = input("password: ")
        print('\033[1A' + ' '*80 + '\r', end='')
        token = s.headers['__RequestVerificationToken']
        state = login(user, pwd, token)
        if state == 0:
            return

    # "Too many attempts. Exiting."
    s_print(x["wro_lgi"][L])
    print()
    exit(2)


def set_start_date(date):
    amount = get_value_from_page(api + 'monitoring/start_date', 'DataLimit')
    r = s.post(api + 'monitoring/start_date', data='<?xml version:"1.0" encoding="UTF-8"?><request>\
        <StartDay>' + str(date) + '</StartDay>\
        <DataLimit>' + amount + '</DataLimit>\
        <MonthThreshold>90</MonthThreshold>\
        <SetMonthData>1</SetMonthData>\
        </request>')
    s.headers.update({'__RequestVerificationToken': r.headers['__RequestVerificationToken']})


def check_login_state():
    state_link = api + 'user/state-login'
    state_int = int(get_value_from_page(state_link, 'State'))
    return(state_int)


def get_value_from_page(address, tag):
    # All values are returned as strings.
    page = s.get(address).text
    pattern = '\<' + tag + '\>(.*)\</' + tag + '\>'
    value = re.findall(pattern, page)
    # The 1st returned match is assumed to be the only one.
    output = value[0]
    return output


def get_month_usage():
    month_stats_link = api + 'monitoring/month_statistics'
    m_dl = float(get_value_from_page(month_stats_link, 'CurrentMonthDownload'))
    m_ul = float(get_value_from_page(month_stats_link, 'CurrentMonthUpload'))
    month_usage = ( m_dl + m_ul ) # in Bytes
    return month_usage


def get_plan_total():
    link = api + 'monitoring/start_date'
    limit_b = int(get_value_from_page(link, 'trafficmaxlimit'))
    limit_user = get_value_from_page(link, 'DataLimit')
    exp = (3 if limit_user.endswith("GB") else 2)
    # Reduce limit b/c the modem assumes MiB/GiB, while Telecel actually uses MB/GB.
    act_limit = round(limit_b * (125 / 128)**exp / 1000 / 1000)
    return act_limit


def cal_data(time_data):
    months = {
        1: ['JANUARY', 'JANVIER', 31],
        2: ['FEBRUARY', 'FÉVRIER', 28],
        3: ['MARCH', 'MARS', 31],
        4: ['APRIL', 'AVRIL', 30],
        5: ['MAY', 'MAI', 31],
        6: ['JUNE', 'JUIN', 30],
        7: ['JULY', 'JUILLET', 31],
        8: ['AUGUST', 'AOÛT', 31],
        9: ['SEPTEMBER', 'SÉPTEMBRE', 30],
        10: ['OCTOBER', 'OCTOBRE', 31],
        11: ['NOVEMBER', 'NOVEMBRE', 30],
        12: ['DECEMBER', 'DÉCEMBRE', 31],
        }

    year = time_data[0]
    month_int = time_data[1]

    rem = year % 4
    if rem == 0:
        months[2][2] = 29
        
    month_name = months[month_int][L]
    month_days = months[month_int][2]
    
    calendar_data = {
        0: year,
        1: month_int,
        2: month_name,
        3: month_days,
        }
    return calendar_data


def get_daily_usage_totals():
    tm_data = [ i for i in localtime() ]
    today = tm_data[2]

    # Create data set for last month using ths month's data
    lm_data = list(tm_data)
    # If this month is January, last month was December
    if tm_data[1] == 1:
        lm_data[1] = 12
    # Otherwise, last month was this month's integer minus 1
    else:
        lm_data[1] = tm_data[1] - 1

    # set date to 1st of month to avoid issues with 31 days vs 30, etc.
    lm_data[2] = 1
    this_month = cal_data(tm_data)[2]
    last_month = cal_data(lm_data)[2]
    last_month_days = cal_data(lm_data)[3]
    
    # Get other days' usage stats
    start_date_link = api + 'monitoring/start_date'
    # retrieve plan start date
    actual_start_date = get_value_from_page(start_date_link, 'StartDay')
    
    # retrieve cumulative amounts by cycling through start dates
    data_usage_cum = {}
    for c in range(1, 32):
        set_start_date(str(c))
        data_usage_cum[c] = round((float(get_month_usage())))

    # Build dictionary of daily usage totals
    """
    data_usage_old = {}
    for d in range(1, 32):
        if d == today:
            data_usage_old[d] = round(data_usage_cum[d] / 1000 / 1000)
        elif d == 1:
            data_usage_old[d] = round((data_usage_cum[d] - data_usage_cum[d + 1]) / 1000 / 1000)
        else:
            data_usage_old[d] = round((data_usage_cum[d - 1] - data_usage_cum[d]) / 1000 / 1000)
    """
    data_usage = {}
    for d in range(1, 32):
        if d == today:
            # Get data directly from today's count.
            data_usage[d] = round(data_usage_cum[d] / 1000 / 1000)
        elif d >= last_month_days and today < last_month_days:
            # For the last day of last month, subtract data used since the first day of this month from that day.
            data_usage[d] = round((data_usage_cum[d] - data_usage_cum[1]) / 1000 / 1000)
        else:
            # For all other days, subtract cumulative data used since the following day from that day.
            data_usage[d] = round((data_usage_cum[d] - data_usage_cum[d + 1]) / 1000 / 1000)


    n = data_usage
    # Show total plan usage
    total_usage = 0
    if int(actual_start_date) < today:
        # total = daily amounts from start_date to today
        for p in range(int(actual_start_date), today + 1):
            total_usage += n[p]
    elif int(actual_start_date) == today:
        # total = today's cumulative amount
        total_usage = round(data_usage_cum[today] / 1000 / 1000)
    elif int(actual_start_date) > today:
        # daily amounts from start_date to end of last month
        for p in range(int(actual_start_date), last_month_days + 1):
            total_usage += n[p]
        # daily amounts from start of this month to today
        for p in range(1, today + 1):
            total_usage += n[p]
    else:
        # this shouldn't exist
        pass

    if int(actual_start_date) <= today:
        start_month = this_month
    else:
        start_month = last_month
        
    mb = x["dt_un_m"][L]
    gb = x["dt_un_g"][L]
        
    start_str = str(actual_start_date) + " " + start_month
    used_str = str(total_usage) + " " + mb + " (" + str(round(total_usage / 1000, 1)) + " " + gb + ")"
    
    limit = get_plan_total()
    left = limit - total_usage
    left_str = str(left) + " " + mb + " (" + str(round(left / 1000, 1)) + " " + gb + ")"
    
    usage_last30 = 0
    for i in n:
        if n[i] >= 0:
            usage_last30 += n[i]
    avg_usage = usage_last30 / len(n)
    avg_str = str(round(avg_usage)) + " " + mb

    # s_print blank line to end line from last s_print
    s_print('')
    print("{0:<14s}{1:<20s}{2:<20s}{3:<16s}".format(x['plan_st'][L], x['dat_usd'][L], x['dat_rem'][L], x['day_avg'][L]))
    print("{0:<14s}{1:<20s}{2:<20s}{3:<16s}\n".format(start_str, used_str, left_str, avg_str))

    # reset plan start date
    set_start_date(actual_start_date)
    
    return n


def draw_calendar(seq, data_usage):
    tm_data = [ i for i in localtime() ]
    today = tm_data[2]
    
    if seq == 0:
        #TODO: needs to be January-proof
        tm_data[1] = tm_data[1] - 1
        # set date to 1st of month to avoid issues with 31 days vs 30, etc.
        tm_data[2] = 1

    year = cal_data(tm_data)[0]
    month_int = cal_data(tm_data)[1]
    month_name = cal_data(tm_data)[2]
    month_days = cal_data(tm_data)[3]
    
    n = data_usage
    first_of_month = str(datetime.date(year, month_int, 1))
    f = first_of_month
    form = "%Y-%m-%d"
    epoch = datetime.datetime(1970, 1, 1)
    epoch_time = (datetime.datetime.strptime(f, form) - epoch).total_seconds()

    f_wday = localtime(epoch_time)[6]
    
    mb = x["dt_un_m"][L]
    
    # Print calendar
    print("\n{0:^70s}".format(month_name + " (" + mb + ")"))
    print("----------------------------------------------------------------------")
    print("    M         T         W         Th        F         Sa        Su    ")
    print("----------------------------------------------------------------------")
    o = f_wday
    t = today + o - 1

    def print_blank():
        print("{0:>10s}".format(' '), end='')
        
    def print_data():
        print("{0:>4s}{1:>4s}{2:>2s}".format("(" + str(d - o + 1) + ')', str(n[d - o + 1]), "  "), end='')
        
    def print_date():
        print("{0:>4s}{1:>6s}".format("(" + str(d - o + 1) + ")", " "), end='')
       
    # 1st row of calendar (dates & data)
    for d in range(7):
        if d < o:
            print_blank()
        elif (seq == 1 and d <= t) or (seq == 0 and d > t):
            print_data()
        else:
            print_date()
    # 2nd row (end 1st row)
    print()

    # 3rd-4th rows
    for d in range(7, 14):
        if (seq == 1 and d <= t) or (seq == 0 and d > t):
            print_data()
        else:
            print_date()
    print()

    # 5th-6th rows
    for d in range(14, 21):
        if (seq == 1 and d <= t) or (seq == 0 and d > t):
            print_data()
        else:
            print_date()
    print()

    # 7th-8th rows
    for d in range(21, 28):
        if (seq == 1 and d <= t) or (seq == 0 and d > t):
            print_data()
        else:
            print_date()
    print()

    # 9th-10th rows
    for d in range(28, 35):
        if d < month_days + o:
            if (seq == 1 and d <= t) or (seq == 0 and d > t):
                try:
                    print_data()
                except KeyError:
                    print_date()
            else:
                print_date()
        else:
            print_blank()
    print()
    # 10th-11th rows
    for d in range(35,42):
        if d < month_days + o:
            if (seq ==1 and d <= t) or (seq == 0 and d > t):
                try:
                    print_data()
                except KeyError:
                    print_date()
            else:
                print_date()
        else:
            print_blank()
    print("\n")


def reboot():
    # "Rebooting."
    s_print(x["reb_now"][L])
    s.post(api + 'device/control', data='<?xml version:"1.0" encoding="UTF-8"?><request><Control>1</Control></request>')


def connect_data():
    connect_payload = '<?xml version="1.0" encoding="UTF-8"?><request><dataswitch>1</dataswitch></request>'
    r = s.post(api + 'dialup/mobile-dataswitch', data=connect_payload)
    s.headers.update({'__RequestVerificationToken': r.headers['__RequestVerificationToken']})
    sleep(5)
    
def disconnect_data():
    disconnect_payload = '<?xml version="1.0" encoding="UTF-8"?><request><dataswitch>0</dataswitch></request>'
    r = s.post(api + 'dialup/mobile-dataswitch', data=disconnect_payload)
    s.headers.update({'__RequestVerificationToken': r.headers['__RequestVerificationToken']})
    sleep(5)


def check_connection_status():
    # get connection status
    # "Checking connection status..."
    s_print(x["gt_conn"][L])
    
    # ConnectionStatus: 900 = data connecting..., 901 = data connected, 902 = data disconnected, ??? = connection failed
    status_page = api + "monitoring/status"

    while int(get_value_from_page(status_page, 'ConnectionStatus')) != 901:
        # status is either "Connecting...", "Disconnected", or "Connection failed. ..."
        if int(get_value_from_page(status_page, 'ConnectionStatus')) == 900:
            # wait, and then check again
            sleep(1)
            continue
        # status is either "Disconnected" or "Connection failed. ..."
        # "Switching data connection on..."
        s_print(x["clk_con"][L])
        connect_data()
        sleep(1)
        #TODO: Need to add an off ramp after so many tries or so much time, e.g. "No service" situation

    if int(get_value_from_page(status_page, 'ConnectionStatus')) != 901:
        # time to give up
        s_print('')
        # "I'm not helping you get any closer to a connection. Press [Enter] to exit.\n"
        input(x["give_up"][L])
        exit(1)


def check_connection_speed():
    # check for 2G or 3G connection speed
    # "Testing whether connection is 2G or 3G..."
    s_print(x["get_spd"][L])
    # CurrentNetworkType: 45 = 3G, 3 = 2G
    status_page = api + "monitoring/status"
    if int(get_value_from_page(status_page, 'CurrentNetworkType')) == 3:
        # reboot modem
        # "Speed is only 2G, rebooting now..."
        s_print(x["not_3gc"][L])
        reboot()
        # "Modem rebooted. Run this app again if problems continue. Press [Enter] to exit."
        s_print('')
        input(x["mod_rbt"][L])
        exit(0)


def internet_check():
    # check for internet connection
    # "Testing internet IP connection..."
    s_print(x["ip_test"][L])
    ip_ping = ping_host(opendns_ip, 2)
    if ip_ping is not True:
        # disconnect & reconnect data (in case new plan needs to be initialized)
        # "No internet. Reconnecting data in case you just bought a new plan."
        s_print(x["new_pln"][L])

        disconnect_data()
        connect_data()
        
        sleep(5)
        ip_ping = ping_host(opendns_ip, 2)
        if ip_ping is not True:
            # "Still no internet. Out of credit? Press [Enter] to exit."
            s_print('')
            input(x["no_cred"][L])
            exit(0)


def dns_check():
    # check for DNS resolution: "Testing internet DNS resolution..."
    s_print(x["dns_chk"][L])
    name_ping = ping_host(named_site, 3)
    if name_ping is not True:
        # "DNS not resolving. Reconnecting data..."
        s_print(x["dns_not"][L])
        # disconnect & reconnect data
        disconnect_data()
        connect_data()
        sleep(5)
        if name_ping is not True:
            # "DNS still not resolving. A reboot might help. Press [Enter] to Exit."
            s_print('')
            input(x["dns_yet"][L])
            exit(1)


def set_plan_amount(amount):
    start_day = get_value_from_page(api + 'monitoring/start_date', 'StartDay')
    r = s.post(api + 'monitoring/start_date', data='<?xml version:"1.0" encoding="UTF-8"?><request>\
        <StartDay>' + start_day + '</StartDay>\
        <DataLimit>' + str(amount) + '</DataLimit>\
        <MonthThreshold>90</MonthThreshold>\
        <SetMonthData>1</SetMonthData>\
        </request>')
    s.headers.update({'__RequestVerificationToken': r.headers['__RequestVerificationToken']})


def run_checks():
    # Get daily usage totals
    data_usage = get_daily_usage_totals()
    
    # Print data in calendars
    draw_calendar(0, data_usage)
    draw_calendar(1, data_usage)

    # Check connection status
    check_connection_status()

    # Check for 2G or 3G connection speed
    check_connection_speed()
    
    # Connection speed is 3G; check for internet connection
    internet_check()
    
    # Internet connection confirmed; check for DNS resolution
    dns_check()
    
    # No problems detected
    s_print('')
    
    # Give further options
    give_options()


def give_options():
    #input("Everything seems fine. Options: ...")
    command = input(x["al_good"][L])
    if command == '':
        exit(0)
    elif command == 'c':
        date = input('Enter start date (day of month; i.e. "1" or "30"): ')
        set_start_date(date)
        print("\n=====================================================================\n")
        run_checks()
    elif command == 'd':
        unit_raw = input('Enter units ("MB" or "GB"): ')
        unit = unit_raw.upper()
        sug = ("3" if unit == 'GB' else "3000")
        qty_raw = input('Enter number of ' + unit + '; i.e. "' + sug + '": ' )
        qty = ''.join(i for i in qty_raw if i.isdigit())
        set_plan_amount(qty + unit)
        print("\n=====================================================================\n")
        run_checks()
    else:
        print("Unrecognized option. ", end='')
        give_options()



# === Set constants =======================================================

opendns_ip = "208.67.220.220"
named_site = "france24.fr"

x = {
    "fal_lgi": ["Login failed. Exiting.",
                "Échec d'authentification. Fin du script."],
    "wro_lgi": ["Too many attempts. Exiting.",
                "Trop d'essaies. Fin du script."],
    "dt_un_m": ["MB",
                "Mo"],
    "dt_un_g": ["GB",
                "Go"],
    "plan_st": ["PLAN START:",
                "DÉBUT:"],
    "dat_usd": ["DATA USED:",
                "CONSOMMATION:"],
    "dat_rem": ["DATA LEFT:",
                "RESTANTES:"],
    "day_avg": ["DAILY AVG:",
                "PAR JOUR:"],
    "reb_now": ["Rebooting now...",
                "En train de redémarrer..."],
    "gt_conn": ["Checking connection status...",
                "En train de chercher l'état de la connexion..."],
    "clk_con": ["Switching data connection on...",
                "Allumage de la connexion de données..."],
    "give_up": ["I'm not helping you get any closer to a connection. Press [Enter] to exit.\n",
                "Mon aide vous est inutile. Tappez [Enter] pour fermer.\n"],
    "get_spd": ["Testing whether connection is 2G or 3G...",
                "En train de vérifier la vitesse de la connexion..."],
    "not_3gc": ["Speed is only 2G, rebooting now...",
                "Connexion à 2G, en train de redémarrer..."],
    "mod_rbt": ["Modem rebooted. Run this app again if problems continue. Press [Enter] to exit.",
                "Modem redémarré. Relancer cette appli en cas des problèmes. Tappez [Enter] pour fermer."],
    "ip_test": ["Testing internet IP connection...",
                "En train de chercher une connexion internet..."],
    "new_pln": ["No internet. Reconnecting data in case you just bought a new plan...",
                "Pas de connexion internet. Reconnexion de données en cas de nouveau forfait..."],
    "no_cred": ["Still no internet. Out of credit? Press [Enter] to exit.",
                "Toujours pas d'internet. Plus de credit ? Tappez [Enter] pour fermer."],
    "dns_chk": ["Testing internet DNS resolution...",
                "Évaluation du fonctionnement du DNS..."],
    "dns_not": ["DNS not resolving. Reconnecting data...",
                "Pas de résolution DNS. Reconnexion de données..."],
    "dns_yet": ["DNS still not resolving. A reboot might help. Press [Enter] to exit.",
                "Toujours pas de résolution DNS. Veuillez redémarrer le modem. Tappez [Enter] pour fermer."],
    "al_good": ["Options:\n[c]\tChange start date\n[d]\tChange data amount\n[Enter]\tQuit\n: ",
                "Options:\n[c]\tChanger de date de départ\n[d]\tChanger de quantité de données\n[Enter]\tQuitter\n:"],
    }



# === Main processing =====================================================

# Print app header
print_app_info()

# Find modem IP, set constants
modem_ip = get_modem_ip()
modem_home = "http://" + modem_ip + "/html/home.html"
api = "http://" + modem_ip + "/api/"

# Check for connection to modem
modem_check(modem_ip)

def post_request(link, xml_payload):
    r = s.post(api + link, data=xml_payload)
    s.headers.update({'__RequestVerificationToken': r.headers['__RequestVerificationToken']})
    print(r.text)
    print(r.status_code)

#<?xml version: "1.0" encoding="UTF-8"?><request><Index>-1</Index><Phones><Phone>75556774</Phone></Phones><Sca></Sca><Content>test2</Content><Length>5</Length><Reserved>1</Reserved><Date>2018-04-02 10:01:18</Date></request>

with requests.session() as s:

    # Set up the session
    h = s.get(modem_home)
    csrf_tokens = grep_csrf(h.text)
    csrf_token = csrf_tokens[0]

    # Build out the headers
    s.headers.update({
        'Cookie': 'SessionID=' + h.cookies['SessionID'],
        '__RequestVerificationToken': csrf_token,
        })

    # Determine language setting
    L = get_language()

    # Log in to modem
    modem_login()

    # Run series of checks
    run_checks()
    
    
    # Send USSD? get error 100002 (not supported or incorrect path)
    """
    post_request(
        'ussd/send',
        '<?xml version="1.0" encoding="UTF-8"?>\
            <request>\
                <content>*168#</content>\
                <codeType>0</codeType>\
                <timeout></timeout>\
            </request>'
        )
    """
    
    # Set to debug mode (this might force a reboot!):
    """
    post_request(
        'device/mode',
        '<?xml version="1.0" encoding="UTF-8"?>\
            <request>\
                <mode>1</mode>\
            </request>'
        )
    """
    
    # Modify DNS (this will force a reboot!):
    #   according to api/monitoring/status, this does not actually change the DNS
    """
    post_request(
        'dhcp/settings', 
        '<?xml version="1.0" encoding="UTF-8"?>\
            <request>\
                <DhcpIPAddress>192.168.100.1</DhcpIPAddress>\
                <DhcpLanNetmask>255.255.255.0</DhcpLanNetmask>\
                <DhcpStatus>1</DhcpStatus>\
                <DhcpStartIPAddress>192.168.100.100</DhcpStartIPAddress>\
                <DhcpEndIPAddress>192.168.100.200</DhcpEndIPAddress>\
                <DhcpLeaseTime>86400</DhcpLeaseTime>\
                <DnsStatus>0</DnsStatus>\
                <PrimaryDns>8.8.8.8</PrimaryDns>\
                <SecondaryDns>8.8.4.4</SecondaryDns>\
            </request>'
        )
    """
    """
    Original content:
    '<?xml version="1.0" encoding="UTF-8"?>\
        <response>\
            <DhcpIPAddress>192.168.100.1</DhcpIPAddress>\
            <DhcpLanNetmask>255.255.255.0</DhcpLanNetmask>\
            <DhcpStatus>1</DhcpStatus>\
            <DhcpStartIPAddress>192.168.100.100</DhcpStartIPAddress>\
            <DhcpEndIPAddress>192.168.100.200</DhcpEndIPAddress>\
            <DhcpLeaseTime>86400</DhcpLeaseTime>\
            <DnsStatus>1</DnsStatus>\
            <PrimaryDns>192.168.8.1</PrimaryDns>\
            <SecondaryDns>192.168.8.1</SecondaryDns>\
        </response>'
    """
    
    # Send SMS (this works!):
    """
    value = '75556774'
    post_request('sms/send-sms',
                 '<?xml version: "1.0" encoding="UTF-8"?>\
                    <request>\
                       <Index>-1</Index>\
                        <Phones><Phone>' + value + '</Phone></Phones>\
                        <Sca></Sca>\
                        <Content>test3</Content>\
                        <Length>5</Length>\
                        <Reserved>1</Reserved>\
                        <Date>2018-04-02 10:01:18</Date>\
                    </request>')
    """

exit(0)
