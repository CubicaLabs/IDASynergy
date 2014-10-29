##############################################################################
#
# IDASynergy 0.1
#
# This module handles the hooks in order to redirect data to IDASynergyIO
# when neccesary.
#
##############################################################################

#import idaapi
from idaapi import *
from idc import *
from idautils import *

class IDAImportFix:
    def __call__(self, f):
        def wrapped_export_f(*args):
            if not globals().has_key("IDP_Hooks") or globals()["IDP_Hooks"] is None:
                from idaapi import IDP_Hooks, UI_Hooks
                from idc import Name, GetFunctionName, GetStrucIdByName, GetConstName, Warning, SetStrucName, GetStrucName
                globals()["IDP_Hooks"] = locals()["IDP_Hooks"]
                globals()["UI_Hooks"] = locals()["UI_Hooks"]
                globals()["Name"] = locals()["Name"]
                globals()["GetFunctionName"] = locals()["GetFunctionName"]
                globals()["GetStrucIdByName"] = locals()["GetStrucIdByName"]
                globals()["GetConstName"] = locals()["GetConstName"]
                globals()["Warning"] = locals()["Warning"]
                globals()["SetStrucName"] = locals()["SetStrucName"]
                globals()["GetStrucName"] = locals()["GetStrucName"]
            return f(*args)
        return wrapped_export_f

class IDASynergyHooksUI(UI_Hooks):

    @IDAImportFix()
    def __init__(self):
        UI_Hooks.__init__(self)
        self.cmdname = "<no command>"

    def preprocess(self, name):
        #print("IDA preprocessing command: %s" % name)
        self.cmdname = name
        return 0

    def postprocess(self):
        #print("IDA finished processing command: %s" % self.cmdname)
        return 0
    
    def saving(self):
        """
        The kernel is saving the database.

        @return: Ignored
        """
        pass
        #print("Saving....")

    def saved(self):
        """
        The kernel has saved the database.

        @return: Ignored
        """
        pass
        #print("Saved")

    def term(self):
        """
        IDA is terminated and the database is already closed.
        The UI may close its windows in this callback.
        
        This callback is best used with a plugin_t with flags PLUGIN_FIX
        """
        #print("IDA terminated")
        pass

    def get_ea_hint(self, ea):
        """
        The UI wants to display a simple hint for an address in the navigation band
        
        @param ea: The address
        @return: String with the hint or None
        """
        #print("get_ea_hint(%x)" % ea)
        pass


class IDASynergyHooksIDP(IDP_Hooks):

    @IDAImportFix()
    def __init__(self):
        IDP_Hooks.__init__(self)

    @IDAImportFix()
    def set_data_io(self, data_io):
        self.data_io = data_io

    @IDAImportFix()
    def renamed(self, ea, new_name, local_name):
        struct_id = GetStrucIdByName(GetConstName(ea))
        is_struct = struct_id != 0xffffffffffffffff and struct_id != 0xffffffff
        if is_struct:
            Warning("IDASynergy still does not support renaming of structs.\nBy renaming it, other collaborators will get this struct deleted and a new one added\nIf you want to avoid this, please rename it to its old name.")
            return IDP_Hooks.renamed(self, ea, new_name, local_name)

        if Name(ea) != "" and GetFunctionName(ea) != "": # If renaming a function...
            self.data_io.apply_modification("functions", (ea, new_name))
            return IDP_Hooks.renamed(self, ea, new_name, local_name)

    @IDAImportFix()
    def undefine(self, ea):
        #print "undef!"
        return IDP_Hooks.undefine(self, ea)

    @IDAImportFix()
    def make_code(self, ea, size):
        return IDP_Hooks.make_code(self, ea, size)

    @IDAImportFix()
    def make_data(self, ea, tid, flags, lent):
        ourtype = ""
        if lent == 1:
            ourtype = "B"
        elif lent == 2:
            ourtype = "D"
        elif lent == 4:
            ourtype == "W"
        if ourtype:
            self.data_io.apply_modification("datadefs", (ea, ourtype))
        return IDP_Hooks.make_data(self, ea, tid, flags, lent)

    @IDAImportFix()
    def add_func(self, func):
        IDP_Hooks.add_func(self, func)
        self.data_io.apply_modification("functions", (func.startEA, GetFunctionName(func.startEA)))
        return 0

    @IDAImportFix()
    def del_func(self, func):
        return IDP_Hooks.del_func(self, func)
        
class IDASynergyHooksIDB(IDB_Hooks):
    @IDAImportFix()
    def byte_patched(self, arg0):
        #print "byte_patched", arg0
        return 0

    @IDAImportFix()    
    def cmt_changed(self, ea, repeatable):
        #print "cmt_changed"
        return 0
        #return IDB_Hooks.cmt_changed(self, ea, repeatable)

    @IDAImportFix()
    def enum_bf_changed(self, arg0):
        #print "enum_bf_changed", arg0
        return 0

    @IDAImportFix()    
    def enum_cmt_changed(self, arg0):
        #print 'enum_cmt_changed', arg0
        return 0

    @IDAImportFix()
    def enum_created(self, arg0):
        #print 'enum_created', arg0
        return 0

    @IDAImportFix()
    def enum_deleted(self, arg0):
        #print 'enum_deleted', arg0
        return 0

    @IDAImportFix()        
    def enum_member_created(self, arg0, cid):
        #print 'enum_member_created', arg0
        return 0

    @IDAImportFix()
    def enum_member_deleted(self, arg0, cid):
        #print 'enum_member_deleted', arg0
        return 0

    @IDAImportFix()
    def enum_renamed(self, arg0):
        #print 'enum_renamed', arg0
        return 0

    @IDAImportFix()
    def func_noret_changed(self, arg0):
        #print 'func_noret_changed', arg0
        return 0

    @IDAImportFix()
    def func_tail_appended(self, arg0, arg1):
        #print 'func_tail_appended', arg0,arg1
        return 0

    @IDAImportFix()
    def func_tail_removed(self, arg0, arg1):
        #print 'func_tail_removed', arg0,arg1
        return 0

    @IDAImportFix()
    def op_ti_changed(self, arg0, arg1, arg2, arg3):
        #print 'op_ti_changed', arg0,arg1,arg2,arg3
        return 0

    @IDAImportFix()
    def op_type_changed(self, arg0, arg1):
        #print 'op_type_changed', arg0,arg1
        return 0

    @IDAImportFix()
    def segm_added(self, arg0):
        #print 'segm_added', arg0
        return 0

    @IDAImportFix()
    def segm_deleted(self, arg0):
        #print 'segm_deleted', arg0
        return 0

    @IDAImportFix()
    def segm_end_changed(self, arg0):
        #print 'segm_end_changed', arg0
        return 0

    @IDAImportFix()
    def segm_moved(self, arg0, arg1, arg2):
        #print 'segm_moved', arg0,arg1,arg2
        return 0

    @IDAImportFix()
    def segm_start_changed(self, arg0):
        #print 'segm_start_changed', arg0
        return 0

    @IDAImportFix()
    def struc_cmt_changed(self, arg0):
        #print 'struc_cmt_changed', arg0
        return 0

    @IDAImportFix()
    def struc_created(self, arg0):
        #print 'struc_created', arg0
        return 0

    @IDAImportFix()
    def struc_deleted(self, arg0):
        #print 'struc_deleted', arg0
        return 0

    @IDAImportFix()
    def struc_expanded(self, arg0):
        #print 'struc_expanded', arg0
        return 0

    @IDAImportFix()
    def struc_member_changed(self, arg0, arg1):
        #print 'struc_member_changed', arg0,arg1
        return 0

    @IDAImportFix()
    def struc_member_created(self, arg0, arg1):
        #print 'struc_member_created', arg0,arg1
        return 0

    @IDAImportFix()
    def struc_member_deleted(self, arg0, arg1, arg2):
        #print 'struc_member_deleted', arg0,arg1,arg2
        return 0

    @IDAImportFix()
    def struc_member_renamed(self, arg0, arg1):
        #print 'struc_member_renamed', arg0,arg1
        return 0

    @IDAImportFix()
    def struc_renamed(self, arg0):
        return 0

    @IDAImportFix()
    def tail_owner_changed(self, arg0, arg1):
        #print 'tail_owner_changed', arg0,arg1
        return 0

    @IDAImportFix()
    def thunk_func_created(self, arg0):
        #print 'thunk_func_created', arg0
        return 0

    @IDAImportFix()
    def ti_changed(self, arg0, arg1, arg2):
        #print 'ti_changed', arg0,arg1,arg2
        return 0

