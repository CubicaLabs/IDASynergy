##############################################################################
#
# IDASynergy 0.1
#
# This module handles importing and exporting of data from IDA to .dat files,
# which are pickl'ed tuples of (ea, data1, ... datan) elements.
#
##############################################################################
#
# TODO
#
# - Enums
# - Maybe using sets instead of lists in the files would prevent unnecessary commits
#   i.e. if the same structures exists in different orders, synergy will don't break
#   anything, but unnecessary commits for structs.dat will happen.

import re
import time
import json
import zipfile
from idc import *
from idautils import *
from idaapi import *

#################################################################
#### IDA Versioning I/O - importers and Exporters
#################################################################

class IDASynergyIO:

    def __init__(self, local_dir):
        # Walks all the class looking for exporters and importers
        self.local_dir = local_dir
        self.importers = []
        self.exporters = []
        self.visitors = []
        self.postimporters = []
        for k in IDASynergyIO.__dict__.keys():
            if "func_name" in dir(IDASynergyIO.__dict__[k]):
                f = IDASynergyIO.__dict__[k]
                if "wrapped_import" in f.func_name:
                    self.importers.append((f.order, f))
                elif "wrapped_export" in f.func_name:
                    self.exporters.append((f.order, f))
                elif "wrapped_visitor" in f.func_name:
                    self.visitors.append((f.order, f))
                elif "wrapped_postimport" in f.func_name:
                    self.postimporters.append((f.order, f))
        # Sort functions by order
        self.exporters.sort()
        self.importers.sort()
        self.visitors.sort()
        self.postimporters.sort()
        self.init_time = 0
        self.cb_import = None
        self.path = ""
        if local_dir:
            self.path = local_dir + os.sep

    def set_chooser_gui_proxy(self, f):
        self.chooser_gui_proxy = f

    def export_all(self):
        init_time = time.time()
        [f(self, []) for w, f in self.exporters] # low cost exporters
        self.walkidc() # high cost exporters
        print "[ ] Elapsed time: %ds" % (time.time() - init_time)

    def import_all(self, cb_done):
        self.init_time = time.time()
        self.cb_import = cb_done
        [f(self) for w, f in self.importers]
        idaapi.register_timer(1000, self.import_timer_cb)

    def import_timer_cb(self):
        # SetStatus returns the current status and IDA sets again the real status
        # after we set IDA_STATUS_READY.
        prev_status = idc.SetStatus(IDA_STATUS_READY)
        if prev_status == IDA_STATUS_READY:
            [f(self) for w, f in self.postimporters]
            print "[ ] Elapsed time: %ds" % (time.time() - self.init_time)
            self.cb_import
            return -1
        return 1000

    def launch_timer_cb(self):
        # SetStatus returns the current status and IDA sets again the real status
        # after we set IDA_STATUS_READY.
        prev_status = SetStatus(IDA_STATUS_READY)
        if prev_status == IDA_STATUS_READY:
            self.startplugin()
            return -1
        return 1000

    def import_from_file(self, filename, cb_import):
        zip_file = zipfile.ZipFile(filename, 'r')
        zip_file.extractall()
        self.import_all(cb_import)
        print "[+] Data analysis has been imported from %s" % filename
        # TODO: Check for existant .dat files to avoid overwrites. Maybe a tempdir can be used

    def export_to_file(self, filename):
        self.export_all() 
        zip_file = zipfile.ZipFile(filename, 'a')
        for filename in [each_file for each_file in os.listdir(self.path) if ".dat" in each_file]:
	       zip_file.write(self.path + filename)
        zip_file.close()
        print "[+] Data analysis has been exported to %s" % filename

    #----------------------------------------------------
    # NOTE/REMINDER: This was too heavy, don't do this.
    #----------------------------------------------------
    # def walk(self):
    #     start_ea = SegStart(list(Segments())[0]) # Get the end of the last segment
    #     end_ea = SegEnd(list(Segments())[-1])    # Get the end of the last segment
    #     res = {}
    #     for w, v in self.visitors:
    #         res[v.real_name] = []

    #     for ea in xrange(start_ea, end_ea, 4):   # It's 4byte aligned
    #         for w, v in self.visitors:
    #             v(self, ea, res[v.real_name])

    #     for w, v in self.visitors:
    #         self.serialize(v.real_name, res[v.real_name])

    def walkidc(self):
        res = {}

        start_ea = SegStart(list(Segments())[0]) # Get the end of the last segment
        end_ea = SegEnd(list(Segments())[-1])    # Get the end of the last segment

        tempfilename = self.path + "tempidasyn.idc"
        GenerateFile(OFILE_IDC, tempfilename, start_ea, end_ea, 0)

        fh = open(tempfilename, "r")
        for w, v in self.visitors:
            res[v.real_name] = []
               
        for line in fh.readlines():
            for w, v in self.visitors:
                v(self, line, res[v.real_name])

        for w, v in self.visitors:
            self.serialize(v.real_name, res[v.real_name])

        fh.close()
        os.unlink(tempfilename)


    def save_hash(self, kind, data):
        fh = open(self.path + "hashes.db", "r+")
        try:
            hashtable = json.loads(fh.read())
        except:
            hashtable = {}
        m = md5.new() 
        m.update(data)
        hashtable[kind] = m.hexdigest()
        fh.write(json.dumps(hashtable))
        fh.close()

    def serialize(self, func_name, data):
        kind = "_".join(func_name.split("_")[1:])
        fh = open(self.path + "%s.dat" % kind, "w")
        data.sort()
        fh.write(json.dumps(data))
        fh.close()
        #self.save_hash(kind, data)
        print "[+] Exported %s" % kind.capitalize()

    def unserialize(self, func_name):
        kind = "_".join(func_name.split("_")[1:])
        fh = open(self.path + "%s.dat" % kind, "r")
        data = json.loads(fh.read())
        fh.close()
        return data

    #################################################################
    #### Decorators 
    #################################################################
    class visitor:
        def __init__(self, order):
            self.order = order

        def __call__(self, f):
            def wrapped_visitor(*args):
                data = f(*args)
                return data
            wrapped_visitor.real_name = f.func_name
            wrapped_visitor.order = self.order
            return wrapped_visitor

    class exporter:
        def __init__(self, order):
            self.order = order

        def __call__(self, f):
            def wrapped_export_f(*args):
                data = f(*args)
                args[0].serialize(f.func_name, data)
                return data
            wrapped_export_f.order = self.order
            return wrapped_export_f

    class importer:
        def __init__(self, order):
            self.order = order

        def __call__(self, f):
            def wrapped_import_f(*args):
                kind = "_".join(f.func_name.split("_")[1:])
                data = args[0].unserialize(f.func_name)
                ret = f(self, data)
                print "[+] %s Imported" % kind.capitalize()
                return ret
            wrapped_import_f.order = self.order
            return wrapped_import_f

    class postimporter:
        def __init__(self, order):
            self.order = order

        def __call__(self, f):
            def wrapped_postimport_f(*args):
                kind = "_".join(f.func_name.split("_")[1:])
                data = args[0].unserialize(f.func_name)
                ret = f(self, data)
                print "[+] %s Imported" % kind.capitalize()
                return ret
            wrapped_postimport_f.order = self.order
            return wrapped_postimport_f


    #################################################################
    #### Exporters
    #################################################################

    @exporter(1)
    def export_functions(self, funcs=[]):
        for funcea in Functions():
            funcs.append((funcea, GetFunctionName(funcea)))
        return funcs

    @exporter(2)
    def export_segs(self, segs=[]):
        for segea in Segments():
            segname = SegName(segea)
            segend = SegEnd(segea)
            s = getseg(segea)
            segs.append((segea, (segend, s.align, s.comb, s.sel, s.use32(), s.use64(), GetConstName(s.sclass), segname)))
        return segs
        
    @exporter(3)
    def export_marks(self, marks=[]):
        for i in range(1,1024):
            addr = GetMarkedPos(i)
            cmt = GetMarkComment(i)
            if addr is not None and cmt is not None:
                marks.append((addr, cmt))
        return marks

    @exporter(4)
    def export_strings(self, strdata=[]):
        s = Strings()
        for i in s:
            references = []
            for ref_ea in DataRefsTo(i.ea):
                comm = Comment(ref_ea)
                if comm:
                    references.append(ref_ea)
            strdata.append((i.ea, (i.length, i.type, references)))
        return strdata

    @exporter(5)
    def export_structs(self, structlist=[]):
        for struct_idx, struct_id, struct_name in Structs():
            members = []
            for member_offset, member_name, member_size in StructMembers(struct_id):
                member_flag = GetMemberFlag(struct_id, member_offset)
                member_cmt = GetMemberComment(struct_id, member_offset, 0)
                member_rpt_cmt = GetMemberComment(struct_id, member_offset, 1)
                members.append((member_offset, (member_name, member_size, member_flag, member_cmt, member_rpt_cmt)))
            # We're indexing structures by names for now, structures are tricky.
            structlist.append((struct_name, (struct_idx, members))) 
        return structlist

    @exporter(6)
    def export_function_comments(self, comment_list=[]):
        for funcea in Functions():
            functionRepetableCmt = GetFunctionCmt(funcea, 1)
            functionNonRepetableCmt = GetFunctionCmt(funcea, 0)

            if functionRepetableCmt:
                comment_list.append((funcea, (GetFunctionCmt(funcea, 1), 1)))

            if functionNonRepetableCmt:
                comment_list.append((funcea, (GetFunctionCmt(funcea, 0), 0)))

        return comment_list


    @visitor(1)
    def export_comments(self, line, comment_list=[]):
        comm_re = re.compile("MakeComm.*?(0X\w+).*?\"(.*)\"", re.DOTALL)
        rpt_comm_re = re.compile("MakeRptCmt.*?(0X\w+).*?\"(.*)\"", re.DOTALL)
        matches = comm_re.findall(line)
        if len(matches) > 0 and matches[0][1] != "":
            comment_list.append((int(matches[0][0], 16), (matches[0][1].decode("string-escape"), 0)))
        matches = rpt_comm_re.findall(line)
        if len(matches) > 0 and matches[0][1] != "":
            comment_list.append((int(matches[0][0], 16), (matches[0][1].decode("string-escape"), 1)))
        return comment_list

    @visitor(2)
    def export_refs(self, line, refs_list=[]):
        comm_re = re.compile("MakeComm.*?(0X\w+).*?\"(.*)\"", re.DOTALL)
        rpt_comm_re = re.compile("MakeRptCmt.*?(0X\w+).*?\"(.*)\"", re.DOTALL)
        matches = comm_re.findall(line)
        ea = None
        if len(matches) > 0 and matches[0][1] != "":
            ea = int(matches[0][0], 16)
        matches = rpt_comm_re.findall(line)
        if len(matches) > 0 and matches[0][1] != "":
            ea = int(matches[0][0], 16)
        refs = []
        if ea is not None:
            for xr in XrefsTo(ea, 0):
                if xr.type != 21:
                    # if type is not ordinary flow
                    refs.append((xr.frm, xr.type, 0))
            for xr in XrefsFrom(ea, 0):
                if xr.type != 21:
                    # if type is not normal flow
                    refs.append((xr.to, xr.type, 1))
        if refs:
            refs_list.append((ea, refs))
        return refs_list

    @visitor(3)
    def export_datadefs(self, line, datadef_list=[]):
        byte_re = re.compile("MakeByte.*?(0X\w+)", re.DOTALL)
        word_re  = re.compile("MakeWord.*?(0X\w+)", re.DOTALL)
        dword_re = re.compile("MakeDword.*?(0X\w+)", re.DOTALL)
        qword_re = re.compile("MakeQword.*?(0X\w+)", re.DOTALL)
        all_re = {byte_re: "B", word_re: "W", dword_re: "D", qword_re: "Q"}
        for current_re in all_re.keys():
            matches = current_re.findall(line)
            if len(matches) > 0 :
                datadef_list.append((int(matches[0], 16), all_re[current_re]))
        return datadef_list

    # @visitor(1)7
    # def visitor_comments(self, ea, comment_list=[]):
    #     prev_comment = "" if not comment_list else comment_list[-1][1]
    #     reg_comment = GetCommentEx(ea,0) # Regular
    #     if reg_comment:
    #         if reg_comment != prev_comment: # As I'm walking byte per byte, I receive the same comment for several bytes
    #             comment_list.append((ea, reg_comment))
    #             prev_comment = reg_comment
    #     return comment_list

    # @visitor(2)
    # def visitor_repeatable(self, ea, comment_list=[]):
    #     prev_comment = "" if not comment_list else comment_list[-1][1]
    #     rep_comment = GetCommentEx(ea,1) # Repeatable
    #     if rep_comment:
    #         if rep_comment != prev_comment: # As I'm walking byte per byte, I receive the same comment for several bytes
    #             comment_list.append((ea, rep_comment))
    #             prev_comment = rep_comment
    #     return comment_list

    # demasiado gigante el file!
    # @visitor(3)
    # def visitor_xrefs_from(self, ea, xrefs_list=[]):
    #     for x in XrefsFrom(ea):
    #         if x.to != ea + 4:
    #             xrefs_list.append((ea, x.to))
    #     return xrefs_list

    # @visitor(4)
    # def visitor_xrefs_to(self, ea, xrefs_list=[]):
    #     for x in XrefsTo(ea):
    #         if x.to != ea + 4:
    #             xrefs_list.append((ea, x.to))
    #     return xrefs_list

    #################################################################
    #### Importers
    #################################################################
                
    @importer(1)
    def import_segs(self, seglist):
        # TODO: Moving the segment is NOT supported,
        #       as we index segments using the segment start.
        seglist_dict = dict(seglist)
        seglist_ea = seglist_dict.keys()
        to_delete = []
        for segea in Segments():
            if segea in seglist_ea:
                s = getseg(segea)
                current_seg_info = {'name': str(SegName(segea)),
                                    'end':  SegEnd(segea),
                                    'align': s.align,
                                    'comb': s.comb,
                                    'sel': s.sel,
                                    'use32': s.use32(),
                                    'use64': s.use64(),
                                    'class': str(GetConstName(s.sclass)) }

                # Todo: probably a better way to do this exists
                segend_new, segalign, scomb, ssel, suse32, suse64, sclass, segname_new = seglist_dict[segea]
                updated_seg_info = {'name': str(segname_new),
                                    'end': segend_new,
                                    'align': segalign,
                                    'comb': scomb,
                                    'sel': ssel,
                                    'use32': suse32,
                                    'use64': suse64,
                                    'class': str(sclass) }

                if current_seg_info['name'] != updated_seg_info['name']:
                    RenameSeg(segea, updated_seg_info['name'])

                if current_seg_info['end'] != updated_seg_info['end']:
                    # FIXME: start can't be changed
                    SetSegBounds(segea, segea, updated_seg_info['end'], idaapi.SEGMOD_SILENT)

                if current_seg_info['align'] != updated_seg_info['align']:
                    SegAlign(segea, updated_seg_info['align'])
                if current_seg_info['comb'] != updated_seg_info['comb']:
                    SegComb(segea, updated_seg_info['comb'])              
                if current_seg_info['class'] != updated_seg_info['class']:
                    SegClass(segea, updated_seg_info['class'])
                if (current_seg_info['use32'] != updated_seg_info['use32']) or (current_seg_info['use64'] != updated_seg_info['use64']):
                   #addressing = 0
                   #addressing = 1 if updated_seg_info['use32'] else 0
                   #addressing = 2 if updated_seg_info['use64'] else addressing
                   addressing = (int(updated_seg_info['use32']) | int(updated_seg_info['use64']) << 1) & 2
                   SetSegAddressing(segea, addressing)

            else:
                # It doesn't exists in the update, so it was deleted
                to_delete.append(segea)

        for segea in to_delete:
            print "[-] Removing segment starting at " + hex(segea).rstrip("L")
            DelSeg(segea, idaapi.SEGMOD_SILENT)

        # So we only add new segments and don't destroy the previous analysis
        for segstart, (segend, align, comb, base, use32, use64, sclass, segname) in seglist:
            if segstart not in Segments():
                addressing = (int(use32) | int(use64) << 1) & 2
                AddSeg(segstart, segend, base, addressing, align, comb)
                RenameSeg(segstart, str(segname))
                SegClass(segea, str(sclass))
        Refresh()
        
    @importer(2)
    def import_marks(self, marks):
        for i, (markea, mark_name) in zip(range(1, len(marks)+1), marks):
            MarkPosition(markea, 0, 0, 0, i, str(mark_name))
            
    @importer(3)
    def import_functions(self, func_list):
        for funcea, func_name in func_list:
            MakeCode(funcea)
            MakeFunction(funcea)
            if not func_name.startswith("sub_") and not func_name.startswith("loc_") and not func_name.startswith("unk_"):
                MakeName(funcea, str(func_name))
     
    @importer(4)
    def import_comments(self, comment_list):
        for ea, (comment, isRep) in comment_list:
            if isRep == 1:
                MakeRptCmt(ea, str(comment))
            else:
                MakeComm(ea, str(comment))

    @importer(7)
    def import_function_comments(self, comment_list):
        for ea, comment, isRep in comment_list:
            if isRep == 1:
                SetFunctionCmt(ea, str(comment), 1)
            elif isRep == 0:
                SetFunctionCmt(ea, str(comment), 0)
        Refresh()

    @importer(5)
    def import_strings(self, strdata):
        for strea, (strlen, strtype, refs) in strdata: 
            MakeStr(strea, strea+strlen)
            for ref_ea in refs:
                add_dref( ref_ea, strea, 4 ) # 4 = data ref

    @importer(6)
    def import_structs(self, structlist):
        #print structlist
        for struct_name, (struct_idx, members) in structlist:

            struct_id = 0
            for struct_idx_x, struct_id_x, struct_name_x in Structs():
                if struct_name == struct_name_x:
                    struct_id = struct_id_x
            if not struct_id:
                struct_id = AddStruc(struct_idx, str(struct_name))

            if (struct_id == 0xffffffff):
                print "[-] Cannot import struct!. Struct name:", struct_name
                continue

            # TODO: Arrays
            offsets_new = [member_offset for member_offset, (member_name, member_size, member_flag, member_cmt, member_rpt_cmt) in members]
            offsets_old = []
            if GetMemberQty(struct_id) > 0:
                offsets_old = [member_offset for member_offset, member_name, member_size in StructMembers(struct_id)]

            to_delete = set(offsets_old) - set(offsets_new)
            for offset_del in to_delete:
                DelStrucMember(struct_id, offset_del)

            for member_offset, (member_name, member_size, member_flag, member_cmt, member_rpt_cmt) in members:
                if member_name is None:
                    continue
                res = AddStrucMember(struct_id, str(member_name), member_offset, member_flag, -1, member_size )
                #print res
                if res < 0:
                    SetMemberName(struct_id, member_offset, str(member_name))
                    out = SetMemberType(struct_id, member_offset, member_flag, -1, 1)
                    if member_cmt is not None:
                        SetMemberComment(struct_id, member_offset, str(member_cmt), 0)
                    if member_rpt_cmt is not None:
                        SetMemberComment(struct_id, member_offset, str(member_rpt_cmt), 1)
        Refresh()

    @postimporter(1)
    def postimport_refs(self, reflist):
        for ea, refs in reflist:
            for ea_ref, xref_type, is_xref_from in refs:
                if XrefTypeName(xref_type).startswith("Code"):
                    if is_xref_from:
                        add_cref(ea, ea_ref, xref_type)
                    else:
                        add_cref(ea_ref, ea, xref_type)
                else:
                    if is_xref_from:
                        add_dref(ea, ea_ref, xref_type)
                    else:
                        add_dref(ea_ref, ea, xref_type)


    @postimporter(2)
    def postimport_datadefs(self, datadef_list):
        for address, data_type in datadef_list:
            if "D" == data_type:
                MakeDword(address)
            elif "W" == data_type:
                MakeWord(address)
            elif "B" == data_type:
                MakeByte(address)
            elif "Q" == data_type:
                MakeQword(address)

            
    def hl_if_needed(self, txt, o1, o2):
        hl_start = "<font color='#FF0000'>"
        hl_end = "</font>"
        if o1 != o2:
            return hl_start + txt + hl_end
        return txt

    def explain_struct(self, structdata, structother):
        ret = ""
        print "------------------------------------"
        print structdata
        print structother
        for i in range(len(structdata)):
            members = dict(structdata[1])
            o_members = dict(structother[1])
            for member_offset in members.keys():
                member_name, member_size, member_flag, member_cmt, member_rpt_cmt = members[member_offset]
                if member_offset in o_members.keys():
                    o_member_name, o_member_size, o_member_flag, o_member_cmt, o_member_rpt_cmt = o_members[member_offset]
                else:
                    o_member_name, o_member_size, o_member_flag, o_member_cmt, o_member_rpt_cmt = members[member_offset]
                ret += "-----------------------------------------<br />"
                ret += self.hl_if_needed("Member Name: " + str(member_name) + "<br />", member_name, o_member_name)
                ret += self.hl_if_needed("Member Size: " + str(member_size) + "<br />", member_size, o_member_size)
                ret += self.hl_if_needed("Member Flag: " + str(member_flag) + "<br />", member_flag, o_member_flag)
                ret += self.hl_if_needed("Member Comment: " + str(member_cmt) + "<br />", member_cmt, o_member_cmt)
                ret += self.hl_if_needed("Member Repeatable Comment: " + str(member_rpt_cmt) + "<br />", member_rpt_cmt, o_member_rpt_cmt)

            return ret


    def explain_segment(self, segdata, segother):
        align_texts = {saAbs: "Absolute segment",
                       saRelByte: "Relocatable, byte aligned",
                       saRelWord: "Relocatable, word (2-byte, 16-bit) aligned",
                       saRelPara: "Relocatable, paragraph (16-byte) aligned",
                       saRelPage: "Relocatable, aligned on 256-byte boundary",
                       saRelDble: "Relocatable, aligned on a double word",
                       saRel4K: "PharLap OMF (4K)",
                       saGroup: "Segment group",
                       saRel32Bytes: "32 bytes",
                       saRel64Bytes: "64 bytes",
                       saRelQword: "8 bytes"}

        comb_texts = {scPriv: "Private",
                      1: "Group",
                      scPub: "Public",
                      3: "Reserved",
                      scPub2: "As defined by Microsoft, same as C=2 (public).",
                      scStack: "Stack",
                      scCommon: "Common",
                      scPub3: "As defined by Microsoft, same as C=2 (public)."}

        addressing_texts = ["16bit segment", "32bit segment", "64bit segment"]

        # TODO: It's evident the need for a IDASynergySegment class..
        segend, align, comb, base, use32, use64, sclass, segname = segdata
        o_segend, o_align, o_comb, o_base, o_use32, o_use64, o_sclass, o_segname = segother

        addressing = (int(use32) | int(use64) << 1) & 2
        o_addressing = (int(o_use32) | int(o_use64) << 1) & 2

        try:
            ret  = self.hl_if_needed("Segment name: " + str(segname) + "<br />", segname, o_segname)
            ret += self.hl_if_needed("Segment class: " + str(sclass) + "<br />", sclass, o_sclass)
            ret += self.hl_if_needed("Segment end address: " + hex(segend).rstrip("L") + "<br />", segend, o_segend)
            ret += self.hl_if_needed("Segment align: " + align_texts[align] + "<br />", align, o_align)
            ret += self.hl_if_needed("Segment combination: " + comb_texts[comb] + "<br />", comb, o_comb)
            ret += self.hl_if_needed("Segment addressing: " + addressing_texts[addressing] + "<br />", addressing, o_addressing)
        except:
            import sys, traceback
            print "Exception in user code:"
            print '-'*60
            traceback.print_exc(file=sys.stdout)
            print '-'*60
        return ret


    def solver(self, conflict_files):
        conflict_data = []
        kind = os.path.splitext(os.path.basename( conflict_files[0] ) )[0]
        for filename in conflict_files:
            fh = open(filename, "r")
            # in most list of tuples, the first element is unique
            data = fh.read()
            conflict_data.append( dict(json.loads(data)) )
            fh.close()

        # search for all the keys
        t_keys = []
        for d in conflict_data:
            t_keys += d.keys()
        t_keys = list(set(t_keys))
        conflict_options = {}

        # make a new dict with a tuple of possible data, since there are only
        # 2 files in conflict.. if they are different, the user must decide.

        kind_explanation = {'functions.dat': 'function name',
                            'comments.dat': 'comment',
                            'datadefs.dat': 'data kind definition',
                            'marks.dat': 'mark',
                            'refs.dat': 'reference',
                            'segs.dat': 'segment',
                            'strings.dat': 'string',
                            'structs.dat': 'struct'
                            }
        chooser_text = "The " + kind_explanation[kind] + " has a conflict"
        merged = {}
        for k in t_keys:
            if conflict_data[0].has_key(k) and conflict_data[1].has_key(k) and conflict_data[0][k] != conflict_data[1][k]:
                if kind == "structs.dat":
                    label = chooser_text + ", Name:  " + k
                    option1 = self.explain_struct(conflict_data[0][k], conflict_data[1][k])
                    option2 = self.explain_struct(conflict_data[1][k], conflict_data[0][k])
                    choosen = self.chooser_gui_proxy(label, (option1, option2))
                elif kind == "segs.dat":
                    label = chooser_text + ", Address: <a href='" + hex(k).rstrip("L") + "'>" + hex(k).rstrip("L") + "</a>"
                    option1 = self.explain_segment(conflict_data[0][k], conflict_data[1][k])
                    option2 = self.explain_segment(conflict_data[1][k], conflict_data[0][k])
                    choosen = self.chooser_gui_proxy(label, (option1, option2))
                elif kind == "comments.dat":
                    label = chooser_text + ", Address: <a href='" + hex(k).rstrip("L") + "'>" + hex(k).rstrip("L") + "</a>"
                    option1 = str(conflict_data[0][k][0])
                    option2 = str(conflict_data[1][k][0])
                    choosen = self.chooser_gui_proxy(label, (option1, option2))
                elif kind == "datadefs.dat":
                    datadefs_dict = {"Q": "Data is defined as QWord",
                                     "D": "Data is defined as DWord",
                                     "W": "Data is defined as Word",
                                     "B": "Data is defined as Byte"}
                    label = chooser_text + ", Address: <a href='" + hex(k).rstrip("L") + "'>" + hex(k).rstrip("L") + "</a>"
                    option1 = datadefs_dict[conflict_data[0][k][0]]
                    option2 = datadefs_dict[conflict_data[1][k][0]]
                    choosen = self.chooser_gui_proxy(label, (option1, option2))
                elif kind == "strings.dat":
                    label = chooser_text + ", Address: <a href='" + hex(k).rstrip("L") + "'>" + hex(k).rstrip("L") + "</a>"
                    print conflict_data[0][k]
                    option1 = GetString(k, conflict_data[0][k][0], conflict_data[0][k][1])
                    option2 = GetString(k, conflict_data[1][k][0], conflict_data[1][k][1])
                    choosen = self.chooser_gui_proxy(label, (option1, option2))                              
                else:
                    print repr(conflict_data[0][k])
                    print repr(conflict_data[1][k])
                    print "k is:", k
                    choosen = self.chooser_gui_proxy(chooser_text + ", Address: <a href='" + hex(k).rstrip("L") + "'>" + hex(k).rstrip("L") + "</a>", (repr(conflict_data[0][k]).lstrip("u'[").rstrip("',0]"), repr(conflict_data[1][k]).lstrip("u'").rstrip("'")) )
                
                if choosen is None:
                    # for fname in conflict_files:
                    #     if fname.endswith(".mine"):
                    #         # move file.dat.mine to file.dat, remove file.dat.mine
                    #         offset = fname.find(".mine")
                    #         os.unlink(fname[:offset])
                    #         os.rename(fname, fname[:offset])
                    #     else:
                    #         # discard 'theirs'
                    #         os.unlink(fname)
                    return

                    #raise Exception("Cannot merge files")

                merged[k] = conflict_data[choosen - 1][k]

            elif conflict_data[0].has_key(k):
                merged[k] = conflict_data[0][k]
            elif conflict_data[1].has_key(k):
                merged[k] = conflict_data[1][k]

        ltuples = merged.items()
        ltuples.sort()

        # on_update (gui, horrible) effectively renames the file, since
        # pysvn doesn't seem to allow merging like this or something.
        self.serialize("export_" + kind + ".solved", ltuples)

    def apply_modification(self, kind, data):
        if kind not in ['structs']:
            fh = open("%s%s.dat" % (self.path, kind), "r")
            current = json.loads(fh.read())
            fh.close()
            current.append((data[0], data[1]))
            self.serialize("export_%s" % kind, current)

        

