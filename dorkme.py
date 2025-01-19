import tkinter as tk
import customtkinter as ctk
import webbrowser

# Dork dictionary - now outside the function
dorks = {
    "Directory Listing": "site:{target} intitle:index.of",
    "Sensitive Files": "site:{target} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini",
    "SQL Errors": "site:{target} intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"Warning: pg_connect()\"",
    "WordPress": "site:{target} inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes",
    "Log Files": "site:{target} ext:log",
    "Backup Files": "site:{target} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup",
    "Login Pages": "site:{target} inurl:login | inurl:signin | intitle:Login | intitle:Signin | inurl:auth",
    "Github": "https://github.com/search?q=%22*{target}%22&type=repositories",
    "Pastebin Results": "site:pastebin.com {target}",
    "Database Files": "site:{target} ext:sql | ext:dbf | ext:mdb",
    "Apache Config Files": "site:{target} filetype:config \"apache\"",
    "Robots.txt File": "https://{target}/robots.txt",
    "Publicly Exposed Documents": "site:{target} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv",
    "Find Pastebin Entries": "site:pastebin.com {target}",
    "Find SWF File (Google)": "site:{target} ext:swf",
    "Find SWF File (Yandex)": "https://yandex.com/search/?text=site:{target}%20mime:swf",
    "Search in OpenBugBounty": "https://www.openbugbounty.org/search/?search={target}",
    "Search in Reddit": "site:reddit.com {target}",
    "Check in CENSYS [IP4]": "https://censys.io/ipv4?q={target}",
    "Search in SHODAN": "https://www.shodan.io/search?query={target}",
    "CVE-2020-0646 SharePoint RCE": ".sharepoint.com/_vti_bin/webpartpages/asmx -docs -msdn -mdsec site:{target}",
    "API Endpoints - WSDL": "site:{target} filetype:wsdl | filetype:WSDL | ext:svc | inurl:wsdl | Filetype: ?wsdl | inurl:asmx?wsdl | inurl:jws?wsdl | intitle:_vti_bin/sites.asmx?wsdl | inurl:_vti_bin/sites.asmx?wsdl",
    "GitHub GIST Searches": "https://gist.github.com/search?q=*.%22{target}%22",
    "phpinfo()": "site:{target} ext:php | intext:phpinfo | intitle:phpinfo /\"published by the PHP Group/\"",
    "Employees on LinkedIn": "site:linkedin.com employees {target}",
    "Finding Backdoors": "site:{target} inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor",
    ".htaccess Sensitive Files": "site:{target} inurl:\"/phpinfo.php\" | inurl:\".htaccess\" | ext:htaccess",
    "Find Subdomains": "site:*.{target} -www",
    "Find Sub-Subdomains": "site:*.*.{target} -www -mail",
    "Check Security Headers": "https://securityheaders.com/?q={target}&followRedirects=on",
    "Apache Structure": "site:{target} ext:action | ext:struts | ext:do | ext:action | ext:struts | ext:do",
    "Install / Setup Files": "site:{target} ext:ini | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config",
    "Open Redirects": "site:{target} inurl:redirect | inurl:url | inurl:next | inurl:return | inurl:src=http | inurl:r=http | inurl:go= | inurl:out= | inurl:link= | inurl:target= | inurl:view= | inurl:callback= | inurl:continue= | inurl:redir | inurl:forward= | inurl:dest= | inurl:destination= | inurl:to= | inurl:img_url= | inurl:load= | inurl:page= | inurl:path= | inurl:site= | inurl:navigate= | inurl:dir= | inurl:action= | inurl:ref= | inurl:folder= | inurl:file= | inurl:open= | inurl:val= | inurl:show= | inurl:doc=",
    "Test CrossDomain": "site:{target} ext:xml | inurl:crossdomain",
    "Gitlab": "site:gitlab.com {target}",
    "Reverse IP Lookup": "https://viewdns.info/reverseip/?host={target}&t=1",
    "3rd Party Exposure": "site:http://ideone.com | site:http://codebeautify.org | site:http://codeshare.io | site:http://codepen.io | site:http://repl.it | site:http://justpaste.it | site:http://pastebin.com | site:http://jsfiddle.net | site:http://trello.com | site:*.atlassian.net | site:bitbucket.org  /\"{target}/\"",
    "Search in Bitbucket and Atlassian": "site:atlassian.net | site:bitbucket.org {target}",
    "Search in StackOverflow": "site:stackoverflow.com {target}",
    "Sourcecode - PublicWWW": "https://publicwww.com/websites/{target}/",
    "WayBackURL\'s": "https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey",
    "Traefik": "site:{target} inurl:traefik",
    "crt.sh": "https://crt.sh/?q={target}",
    "Cloud Storage and Buckets": "site:{target} intext:\"cloud storage\"",
    "Plaintext Password Leak": "site:{target} intext:passwd | site:throwbin.io {target} inurl: .txt | intext: password | intext: pwd | intext: passwd | intext: pass | intext: passwords | intext: credentials",
    "s3 Buckets": "site:{target} inurl:s3.amazonaws.com | inurl:bucket | inurl:amazonaws | inurl:cloudfront | site:.s3.amazonaws.com \"{target}\"",
    "What CMS?": "https://whatcms.org/?s={target}",
}

# Initialize the application
app = ctk.CTk()
app.geometry("400x500")
app.title("Google Dorks Generator")

# Title Label
title_label = ctk.CTkLabel(app, text="Google Dorks Generator", font=("Arial", 20), text_color="white")
title_label.pack(pady=10)

# Target Input Field
target_label = ctk.CTkLabel(app, text="Enter Target:", font=("Arial", 14), text_color="white")
target_label.pack(pady=(5, 2))  # Reduced padding

entry_target = ctk.CTkEntry(app, width=200, font=("Arial", 14))
entry_target.pack(pady=(2, 0))  # Reduced padding, less gap between target input and next title

# Dork Dropdown Menu
dork_label = ctk.CTkLabel(app, text="Select Dork Type:", font=("Arial", 14), text_color="white")
dork_label.pack(pady=(2, 5))  # Reduced padding for tighter spacing

# Create a scrollable frame
frame = ctk.CTkFrame(app)
frame.pack(pady=5, fill="both", expand=True, anchor="center")

# Scrollbar setup
scrollbar = ctk.CTkScrollbar(frame, orientation="vertical")
scrollbar.pack(side="right", fill="y")

# Create Listbox
dork_options = sorted(list(dorks.keys()))  # Get the dork options dynamically from the keys of the dorks dictionary

listbox_dork = tk.Listbox(
    frame, 
    height=4, 
    font=("Arial", 14), 
    yscrollcommand=scrollbar.set, 
    bg="black",  # Background color
    fg="white",  # Text color
    selectbackground="gray",  # Highlight color for selection
    selectforeground="white",
    justify="center",
    width=200
)

for option in dork_options:
    listbox_dork.insert("end", option)
listbox_dork.pack(side="left", fill="both", expand=True, anchor="center")

# Link scrollbar to listbox
scrollbar.configure(command=listbox_dork.yview)

# Generate Button
generate_button = ctk.CTkButton(app, text="Generate Dork", font=("Arial", 14), command=lambda: generate_dork())
generate_button.pack(pady=20)

# Function to open the Google search in Chrome
def open_search(query):
    url = f"https://www.google.com/search?q={query}"
    webbrowser.open(url)

# Function to generate the dork based on the selected option
def generate_dork():
    try:
        selected_index = listbox_dork.curselection()[0]
        selected_dork = dork_options[selected_index]
        target = entry_target.get()
        if not target:
            return

        query = dorks.get(selected_dork).format(target=target)
        if query:
            if query.startswith("http://") or query.startswith("https://"):
                webbrowser.open(query)
            else:
                open_search(query)
    except IndexError:
        print("No option selected.")

# Run the application
app.mainloop()