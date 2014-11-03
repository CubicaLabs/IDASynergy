#################################################
#
# IDASynergy 0.1
# This module handles the UI and the SVN client.
#
#################################################

import re
import sys
import glob
import shutil
from idc import *
from idautils import *
from idaapi import *
import idc
import idautils
import idaapi
import time
import thread
import threading
import os, os.path
import ConfigParser
import IDASynergyIO
import IDASynergyClient
from idaapi import Form
from IDASynergyHooks import IDASynergyHooksIDB, IDASynergyHooksIDP, IDASynergyHooksUI

"""
This is both the main and the GUI module
"""

# class threaded:
#     def __call__(self, f):
#         def wrapper(*args):
#             print repr(args)
#             thread.start_new_thread(f, args)
#             print "salgo"
#             return 1
#         return wrapper


# based on http://code.google.com/p/idapython/source/browse/trunk/examples/ex_askusingform.py
try:
    from PySide.QtUiTools import QUiLoader
    from PySide.QtGui import QFileDialog, QWidget, QListWidgetItem, QMovie, QImageReader, QSizePolicy, QPalette
    from PySide.QtCore import Qt, QUrl, Qt
    pyside_loaded = True

    class dialog:
        def __call__(self, f):
            # The .ui files do not load unless I change both the setWorkingDirectory for the loader
            # and for python itself. Maybe programmer problem, maybe IDA problem, who knows,
            # this wrapper fixes the problem.
            def wrapper(*args):
                path = os.path.dirname(__file__)
                ui_path = os.path.join(path, "ui")
                old_wd = os.getcwd()
                os.chdir(ui_path)
                args[0].loader.setWorkingDirectory(ui_path)
                f(args[0])
                os.chdir(old_wd)
            return wrapper

    class IDASynergyConfigUI(QWidget):
        def __init__(self, cb_ok, cb_fail): 
            super(IDASynergyConfigUI, self).__init__()
            self.loader = QUiLoader()
            self.initUI()
            self.ui.buttonBox.accepted.connect(cb_ok)
            self.ui.buttonBox.rejected.connect(cb_fail)
        

        def selectFile(self):
            self.ui.localCopy.setText(QFileDialog.getExistingDirectory())

        def set_controls(self, (rep_url, local_dir, username, password, isSVN)):
            isSVN = True if isSVN == 'True' else False
            self.ui.repoURL.setText(rep_url)
            self.ui.localCopy.setText(local_dir)
            self.ui.svnUsername.setText(username)
            self.ui.svnPassword.setText(password)
            self.ui.checkSVN.setChecked(isSVN)
            self.set_enabledisable_svn_options(isSVN)

        def get_dialog_values(self):
            return self.ui.repoURL.text(), self.ui.localCopy.text(), self.ui.svnUsername.text(), self.ui.svnPassword.text(), self.ui.checkSVN.isChecked()

        def do_modal(self):
            self.ui.show()
            #self.ui.exec_()
            return 0

        def set_enabledisable_svn_options(self, state):
            if not state:
                self.ui.warning_label.setText("<center><font color='#FF0000'>WARNING: If you are using a versioning system other than SVN, you have to manually manage<br />the local repository. Use the <i>load from local repository</i> option in the File menu</font></center>")
            else:
                self.ui.warning_label.setText("")
            self.ui.repoURL.setEnabled(state)
            self.ui.svnUsername.setEnabled(state)
            self.ui.svnPassword.setEnabled(state)

        def checkSVNClicked(self):
            self.set_enabledisable_svn_options(self.ui.checkSVN.isChecked())

        @dialog()
        def initUI(self):
            self.ui = self.loader.load("config.ui")
            self.ui.pushButton.clicked.connect(self.selectFile)
            self.ui.checkSVN.clicked.connect(self.checkSVNClicked)

    class IDASynergyCommitUI(QWidget):
        def __init__(self, cb_ok, cb_fail):
            super(IDASynergyCommitUI, self).__init__()
            self.loader = QUiLoader()
            self.initUI()
            self.ui.buttonBox.accepted.connect(cb_ok)
            self.ui.buttonBox.rejected.connect(cb_fail)

        def set_controls(self, updated_files):
            for to_update in updated_files:
                item = QListWidgetItem('[%s] %s' % to_update)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                #if to_update[0] == "U":
                #    item.setCheckState(Qt.Unchecked)
                #else:
                item.setCheckState(Qt.Checked)
                self.ui.listFiles.addItem(item)

        def get_dialog_values(self):
            listitem_re = re.compile("\[(\w)\]\ (.*)")
            listItems = []
            for i in range(self.ui.listFiles.count()):
                item = self.ui.listFiles.item(i)
                checked = item.checkState() == Qt.Checked
                splitted = listitem_re.findall(item.text())[0]
                listItems.append((checked, splitted[0], splitted[1]))
            return self.ui.commitMessage.toPlainText(), listItems

        def do_modal(self):
            self.ui.show()
            #self.ui.exec_()
            return 0

        def clear_controls(self):
            self.ui.listFiles.clear()

        @dialog()
        def initUI(self):
            self.ui = self.loader.load("commit.ui")


    class IDASynergyLogUI(QWidget):
        def __init__(self):
            super(IDASynergyLogUI, self).__init__()
            self.loader = QUiLoader()
            self.initUI()

        def do_modal(self, cb_ok, cb_fail):
            self.ui.show()
            self.ui.exec_()
            return 0

        @dialog()
        def initUI(self):
            self.ui_path = os.path.dirname(sys.argv[0]) + os.path.sep + "ui" + os.path.sep
            self.ui = self.loader.load("browselog.ui")

    class IDASynergyWaitUI(QWidget):
        def __init__(self):
            super(IDASynergyWaitUI, self).__init__()
            self.loader = QUiLoader()
            self.initUI()

        def do_modal(self):
            self.ui.show()
            #self.ui.exec_()
            self.ui.open()
            return 0

        @dialog()
        def initUI(self):
            self.ui_path = os.path.dirname(sys.argv[0]) + "/ui/"
            self.ui = self.loader.load("wait.ui")

    class IDASynergyChooserUI(QWidget):

        def __init__(self):
            super(IDASynergyChooserUI, self).__init__()
            self.loader = QUiLoader()
            self.initUI()
            self.result = None

        def set_controls(self, prompt, option_list):
            self.ui.labelMessage.setText(prompt)
            self.ui.labelMessage.linkActivated.connect(self.jump_user_to)
            self.ui.option1.setHtml(option_list[0])
            self.ui.option2.setHtml(option_list[1])

        def jump_user_to(self, where):
            print "[+] Jumping to", where
            idc.Jump(int(where, 16))

        def ask(self, prompt, option_list):
            self.set_controls(prompt, option_list)
            self.do_modal(self.cb_use, self.cb_cancel)
            return self.result

        def cb_use(self):
            if self.ui.radioButton1.isChecked():
                self.result = 1
            else:
                self.result = 2
            self.ui.hide()

        def cb_cancel(self):
            self.result = None
            print "[-] Aborted"
            self.ui.hide()

        def get_dialog_values(self):
            return self.ui.option1

        def cb_radio_selected(self):
            self.ui.btnUse.enabled = True

        def do_modal(self, cb_select, cb_cancel):
            print "do_modal start"
            self.ui.btnUse.enabled = False
            self.ui.btnUse.clicked.connect(cb_select)
            self.ui.btnCancel.clicked.connect(cb_cancel)
            self.ui.radioButton1.clicked.connect(self.cb_radio_selected)
            self.ui.show()
            self.ui.exec_()
            return 0

        # def clear_controls(self):
        #     self.ui.listFiles.clear()

        @dialog()
        def initUI(self):
            self.ui = self.loader.load("choose.ui")
except:
    print "[!] In order to run IDASynergy you'll need to get a modified version of PySide that works with your version of IDA.\n    See https://www.hex-rays.com/products/ida/support/download.shtml"
    pyside_loaded = False

class IDASynergyConfig:
    def __init__(self):
        self.filename = "IDASynergy.cfg"
        self.config = ConfigParser.ConfigParser()

    def get(self, attr):
        found = self.config.read(self.filename)
        if found:
            try:
                return self.config.get("IDASynergy", attr)
            except:
                return None
        return None

    def get_config_values(self):
        found = self.config.read(self.filename)
        if not found:
            print "[+] Creating config file"
            self.config.add_section("IDASynergy")
            self.set_config_values(("", "", "", "", "" ))
        else:
            try:
                rep_url = self.config.get("IDASynergy", "RepURL")
                local_dir = self.config.get("IDASynergy","LocalDir")
                username = self.config.get("IDASynergy","Username")
                password = self.config.get("IDASynergy","Password")
                isSVN = self.config.get("IDASynergy","isSVN")
                return rep_url, local_dir, username, password, isSVN
            except:
                print "[!] IDASynergy: There was a problem reading the config file"

        return "", "", "", "", ""

    def set_config_values(self, (rep_url, local_dir, username, password, isSVN)):
        # TODO: Error handling
        self.config.set("IDASynergy", "RepURL", rep_url)
        self.config.set("IDASynergy", "LocalDir", local_dir)
        self.config.set("IDASynergy", "Username", username)
        self.config.set("IDASynergy", "Password", password)
        self.config.set("IDASynergy", "isSVN", isSVN)
        fh = open("IDASynergy.cfg", "w")
        self.config.write(fh)
        fh.close()

class IDASynergyMenu:
    def __init__(self):
        self.config = IDASynergyConfig()
        self.config_gui = IDASynergyConfigUI(self.callback_config_ok, self.callback_config_fail)
        self.commit_gui = IDASynergyCommitUI(self.callback_commit_ok, self.callback_config_fail)
        self.browselog_gui = IDASynergyLogUI()
        self.chooser_gui = IDASynergyChooserUI()
        #self.wait_gui = IDASynergyWaitUI()
        self.versioning_client = None
        self.enable_menu_item = None
        self.svn_menuitems = []
        self.ex_addmenu_item_ctx = []

    def start_config(self):
        self.config.get_config_values()
        self.update_data_from_config()

    def initial_checkout_or_commit(self):
        if self.versioning_client.repository_is_empty():
            # TODO: Ask the user whether to create an initial commit or not
            pass
        else:
            self.on_checkout()

    def update_data_from_config(self):
        global vh_idp # Yes, we're working on it. Look at the version number! :)
        self.local_dir = self.config.get("LocalDir")
        self.rep_url = self.config.get("RepURL")
        self.isSVN = True if self.config.get("isSVN") == "True" else False

        if self.versioning_client is None:
            self.versioning_client = IDASynergyClient.IDASynergyClient(self.config.get("Username"), self.config.get("Password"), self.local_dir, self.rep_url)
            #self.initial_checkout_or_commit()
        else:
            self.versioning_client.update_connection_data(self.config.get("Username"), self.config.get("Password"), self.local_dir, self.rep_url)
            if self.rep_url != self.versioning_client.get_rep_url():
                print "[!] Repository connection information changed"
                #self.initial_checkout_or_commit()
        self.data_io = IDASynergyIO.IDASynergyIO(self.local_dir)
        vh_idp.set_data_io(self.data_io)
        self.data_io.set_chooser_gui_proxy(self.chooser_gui.ask)
        self.versioning_client.set_conflict_solver(self.data_io.solver)

    def config_main(self):
        values = self.config.get_config_values()
        self.config_gui.set_controls(values)
        self.config_gui.do_modal()

    def callback_config_ok(self):
        values = self.config_gui.get_dialog_values()
        self.config.set_config_values(values)
        self.update_data_from_config()
        self.insert(["full"])
        if self.isSVN:
            self.insert(["svn"])
            Warning("You can start using IDASynergy now.\n\n\t*If this is the first commit of the project, please use the \"IDASynergy SVN Commit\" option in the File menu\n\n\t* If you need to checkout the project, please use the \"SVN Checkout\" option in the File menu\n\n\t* If the project is already checked-out in your local copy, use the \"Load from local repository\" option instead\n\n\t* You can update the local copy using the \"SVN update\" option")
        else:
            self.remove(["svn"])
            Warning("You can start using IDASynergy now.\n\n\t* As your version control software is not SVN, you will need to manually manage your repository\n\n\t* Use the \"Load from local repository\" option whenever you want to import changes to IDA")
        print "[+] Config saved"        

    def callback_config_fail(self):
        print "[-] Aborted"

    # UI (Menu) connections
    def on_config(self):
        self.config_main()
        return 1

    def on_checkout(self):
        # TODO: Chequear parametros, fallback a mostrar el config menu
        self.remove_hooks()
        if self.versioning_client.is_working_copy(self.local_dir):
            print "[-] Cannot perform checkout over an already-checked-out local copy"
            print "    Please run update instead, or change your local copy folder"
            self.insert_hooks()
        else:
            print "[ ] IDASynergy checkout repository"
            try:
                self.versioning_client.checkout()
                self.data_io.import_all(self.insert_hooks)
                print "[+] Checkout done!"
            except Exception, e:
                import sys, traceback
                print "Exception in user code:"
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60
                print e, e.__class__, repr(e)
                print "[-] Checkout failed, check your SVN settings: " + str(e)
            
        return 1

    def callback_commit_ok(self):
        commit_message, file_data = self.commit_gui.get_dialog_values()
        commit_files = []
        for to_update in file_data:
            if to_update[0]:
                commit_files.append(to_update[2])
                if to_update[1] == "U":
                    self.versioning_client.add(to_update[2])
                    print "[+] Added %s" % to_update[2]
        try:
            self.versioning_client.commit(commit_files, commit_message)
        except Exception, e:
            import sys, traceback
            print "Exception in user code:"
            print '-'*60
            traceback.print_exc(file=sys.stdout)
            print '-'*60
            print e, e.__class__, repr(e)
        print "[+] Commit done"

    def remove_hooks(self):
        print "[+] IDASynergy Hooks unloaded"
        vh_idb.unhook()
        vh_idp.unhook()
        vh_ui.unhook()

    def insert_hooks(self):
        print "[+] IDASynergy Hooks loaded"
        vh_idb.hook()
        vh_idp.hook()
        vh_ui.hook()

    def on_commit(self):
        # TEMPORAL, los hooks deberian haber seteado los files a esta altura
        if not self.versioning_client.is_working_copy(self.local_dir):
            print "[!] " + self.local_dir + " is not a working copy. Performing checkout..."
            try:
                self.on_checkout()
                self.on_commit()
            except:
                print "[!] Checkout failed! please check your settings"
                self.on_config()
                try:
                    self.on_checkout()
                    self.on_commit()
                except:
                    pass
        else:
            self.remove_hooks()
            self.data_io.export_all()
            self.insert_hooks()            
            if self.on_update():
                to_commit = self.versioning_client.files_to_commit()

                if to_commit == []:
                    print "[!] No files to commit detected."
                    print "    Perform an export if you are starting the repository, or a checkout if you forgot."
                    print "    Or simply modify something in order to have something to commit :-)"
                    return

                self.commit_gui.clear_controls()
                self.commit_gui.set_controls(to_commit)
                self.commit_gui.do_modal()
        return 1


    # @threaded()
    def on_update(self):
        print "[ ] IDASynergy update repository"
        global vh_idb, vh_idp, vh_ui
        self.remove_hooks()
        rev, updated_files = self.versioning_client.update()
        print "[!] Updated to revision " + str(rev[0].number)

        import_funcs = []
        for filename, fileext, fullfilename in updated_files:
            if fileext == ".dat":
                file_with_path = os.path.splitext(fullfilename)[0]
                if os.path.exists( file_with_path + ".dat.solved.dat"):
                    os.unlink(file_with_path + ".dat")
                    os.rename(file_with_path + ".dat.solved.dat", file_with_path + ".dat")
                try:
                    func = getattr(getattr(IDASynergyIO, "IDASynergyIO"), "import_" + filename)
                except:
                    func = getattr(getattr(IDASynergyIO, "IDASynergyIO"), "postimport_" + filename)
                import_funcs.append((func.order, func))
        import_funcs.sort()

        for order, f in import_funcs:
            #print repr(f)
            f(self.data_io)

        self.insert_hooks()
        return 1
        
    def callback_log_ok(self):
        print "Not implemented yet"
        return

    def on_log(self):
        self.browselog_gui.do_modal(self.callback_log_ok, self.callback_config_fail)
        return 1

    def on_export(self):
        Warning("This export option generates an .ivz file that you have to distribute manually.\nIDASynergy won't automatically synchronize unless a local repository is synched\nto a versioning server and the 'IDASynergy SVN Commit' menu option is used.")
        exp_file = idc.AskFile(1, "*.ivz", "Exported data filename")
        print time.time()
        self.remove_hooks()
        self.data_io.export_to_file(exp_file)
        self.insert_hooks()
        return 1

    def on_import(self):
        imp_file = idc.AskFile(0, "*.ivz", "Select file to import")
        self.remove_hooks()
        self.data_io.import_from_file(imp_file, self.insert_hooks)
        return 1	      

    def on_import_all(self):
        self.remove_hooks()
        self.data_io.import_all(self.insert_hooks)
        return 1          

    def on_enable_plugin(self):
        if idc.GetIdbPath():
            menu.start_config()
            self.on_config()
        else:
            print "[-] Activate IDASynergy after the file is loaded and the autoanalysis is finished."

    def insert(self, option_groups=[]):
        if "enable" in option_groups:
            self.enable_menu_item = idaapi.add_menu_item("FILE/", "Enable IDASynergy for this IDB", "", 0, self.on_enable_plugin, ())
            #self.remove_hooks()
        else:
            if "svn" in option_groups and self.svn_menuitems == []:
                self.svn_menuitems.append( idaapi.add_menu_item("FILE/", "IDASynergy SVN Checkout...", "", 0, self.on_checkout, ()) )
                self.svn_menuitems.append( idaapi.add_menu_item("FILE/", "IDASynergy SVN Commit...", "CTRL+SHIFT+C", 0, self.on_commit, () ))
                self.svn_menuitems.append( idaapi.add_menu_item("FILE/", "IDASynergy SVN Update...", "CTRL+SHIFT+U", 0, self.on_update, () ))
            if "full" in option_groups and self.ex_addmenu_item_ctx == []:
                self.ex_addmenu_item_ctx.append( idaapi.add_menu_item("Options/", "IDASynergy...", "", 0, self.on_config, ()) )
                self.ex_addmenu_item_ctx.append( idaapi.add_menu_item("FILE/", "IDASynergy Load from local repository", "", 0, self.on_import_all, ()) )
                self.ex_addmenu_item_ctx.append( idaapi.add_menu_item("FILE/", "IDASynergy Export analysis to file", "", 0, self.on_export, ()) )
                self.ex_addmenu_item_ctx.append( idaapi.add_menu_item("FILE/", "IDASynergy Import analysis from file", "", 0, self.on_import, ()))
                #self.insert_hooks()
                self.remove(["enable"])

    def remove(self, option_groups):
        if "enable" in option_groups:
            if self.enable_menu_item:
                idaapi.del_menu_item(self.enable_menu_item)
        if "svn" in option_groups:
            for x in self.svn_menuitems:
                idaapi.del_menu_item(x)
                self.svn_menuitems = []
        if "full" in option_groups:
            for x in self.ex_addmenu_item_ctx:
                idaapi.del_menu_item(x)
            self.ex_addmenu_item_ctx = []

vh_idb, vh_idp, vh_ui, menu = None, None, None, None

def create_menu():
    global vh_idb, vh_idp, vh_ui, menu 
    if pyside_loaded:
        menu = IDASynergyMenu()
        vh_idb = IDASynergyHooksIDB()
        vh_idp = IDASynergyHooksIDP()
        vh_ui = IDASynergyHooksUI()

        if not menu.config.get("isSVN"):
            menu.remove(["full", "svn"])
            menu.insert(["enable"])
        else:
            menu.start_config()
            menu.insert(["full"])
            if menu.isSVN:
                menu.insert(["svn"])
            menu.remove(["enable"])

        print "[+] IDASynergy loaded"

already_loaded = False

def wait_ready():
    global already_loaded
    if menu is None:
        if os.path.dirname(idautils.GetIdbDir()) == os.getcwd():
            create_menu()

    # Couldn't find a better way: IDA Hooks do not provide any event to
    # know when this happens. To be improved.
    prev_status = idc.SetStatus(IDA_STATUS_READY)
    idc.SetStatus(prev_status)

    if prev_status == IDA_STATUS_READY and (menu is not None):
        if not already_loaded:
            already_loaded = True
            menu.insert_hooks()
        return 0

    return 1000

def start_plugin():
    idaapi.register_timer(1000, wait_ready)
