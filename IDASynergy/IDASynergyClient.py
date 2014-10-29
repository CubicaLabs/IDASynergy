import pysvn
import os.path
import types

class IDASynergyClient:
    """ This class interacts with the versioning server,
        checkout, commit and update methods must be implemented,
        also, a way to get the conflicted files must be implemented.

        It currently works with PySVN, but honoring the interface, it
        should be possible to adapt it to any versioning software.
    """
    def __init__(self, username, password, local_dir, rep_url):
        self.update_connection_data(username, password, local_dir, rep_url)
        self.svn_client = pysvn.Client()
        self.svn_client.exception_style = 1
        self.svn_client.callback_ssl_server_trust_prompt = self.ssl_server_trust_prompt
        self.svn_client.callback_get_login = self.get_login
        self.svn_client.callback_notify = self.callback_notify
        if hasattr( self.svn_client, 'callback_conflict_resolver' ):
            self.svn_client.callback_conflict_resolver = self.callback_conflict_resolver
        self.prepare_action_map()
        self.updated_files = []

    def get_rep_url(self):
        return self.rep_url

    def update_connection_data(self, username, password, local_dir, rep_url):
        if rep_url.startswith("svn+ssh://") and not "@" in rep_url:
            rep_url = rep_url.replace("svn+ssh://", "")
            rep_url = "svn+ssh://" + username + "@" + rep_url
        self.username = username
        self.password = password
        self.local_dir = local_dir
        self.rep_url = rep_url

    def prepare_action_map(self):
        self.wc_notify_action_map = {
            pysvn.wc_notify_action.add: 'A',
            pysvn.wc_notify_action.commit_added: 'A',
            pysvn.wc_notify_action.commit_deleted: 'D',
            pysvn.wc_notify_action.commit_modified: 'M',
            pysvn.wc_notify_action.commit_postfix_txdelta: None,
            pysvn.wc_notify_action.commit_replaced: 'R',
            pysvn.wc_notify_action.copy: 'c',
            pysvn.wc_notify_action.delete: 'D',
            pysvn.wc_notify_action.failed_revert: 'F',
            pysvn.wc_notify_action.resolved: 'R',
            pysvn.wc_notify_action.restore: 'R',
            pysvn.wc_notify_action.revert: 'R',
            pysvn.wc_notify_action.skip: 'skip',
            pysvn.wc_notify_action.status_completed: None,
            pysvn.wc_notify_action.status_external: 'X',
            pysvn.wc_notify_action.update_add: 'A',
            pysvn.wc_notify_action.update_completed: None,
            pysvn.wc_notify_action.update_delete: 'D',
            pysvn.wc_notify_action.update_external: 'X',
            pysvn.wc_notify_action.update_update: 'U',
            pysvn.wc_notify_action.annotate_revision: 'A',
        }
        # new in svn 1.4?
        if hasattr( pysvn.wc_notify_action, 'locked' ):
            self.wc_notify_action_map[ pysvn.wc_notify_action.locked ] = 'locked'
            self.wc_notify_action_map[ pysvn.wc_notify_action.unlocked ] = 'unlocked'
            self.wc_notify_action_map[ pysvn.wc_notify_action.failed_lock ] = 'failed_lock'
            self.wc_notify_action_map[ pysvn.wc_notify_action.failed_unlock ] = 'failed_unlock'

        # new in svn 1.5
        if hasattr( pysvn.wc_notify_action, 'exists' ):
            self.wc_notify_action_map[ pysvn.wc_notify_action.exists ] = 'exists'
            self.wc_notify_action_map[ pysvn.wc_notify_action.changelist_set ] = 'changelist_set'
            self.wc_notify_action_map[ pysvn.wc_notify_action.changelist_clear ] = 'changelist_clear'
            self.wc_notify_action_map[ pysvn.wc_notify_action.changelist_moved ] = 'changelist_moved'
            self.wc_notify_action_map[ pysvn.wc_notify_action.foreign_merge_begin ] = 'foreign_merge_begin'
            self.wc_notify_action_map[ pysvn.wc_notify_action.merge_begin ] = 'merge_begin'
            self.wc_notify_action_map[ pysvn.wc_notify_action.update_replace ] = 'update_replace'


        if hasattr( pysvn.wc_notify_action, 'property_added' ):
            self.wc_notify_action_map[ pysvn.wc_notify_action.property_added ] = 'property_added'
            self.wc_notify_action_map[ pysvn.wc_notify_action.property_modified ] = 'property_modified'
            self.wc_notify_action_map[ pysvn.wc_notify_action.property_deleted ] = 'property_deleted'
            self.wc_notify_action_map[ pysvn.wc_notify_action.property_deleted_nonexistent ] = 'property_deleted_nonexistent'
            self.wc_notify_action_map[ pysvn.wc_notify_action.revprop_set ] = 'revprop_set'
            self.wc_notify_action_map[ pysvn.wc_notify_action.revprop_deleted ] = 'revprop_deleted'
            self.wc_notify_action_map[ pysvn.wc_notify_action.merge_completed ] = 'merge_completed'
            self.wc_notify_action_map[ pysvn.wc_notify_action.tree_conflict ] = 'tree_conflict'
            self.wc_notify_action_map[ pysvn.wc_notify_action.failed_external ] = 'failed_external'

        if hasattr( pysvn.wc_notify_action, 'update_started' ):
            self.wc_notify_action_map[ pysvn.wc_notify_action.update_started ] = 'update_started'
            self.wc_notify_action_map[ pysvn.wc_notify_action.update_skip_obstruction ] = 'update_skip_obstruction'
            self.wc_notify_action_map[ pysvn.wc_notify_action.update_skip_working_only ] = 'update_skip_working_only'
            self.wc_notify_action_map[ pysvn.wc_notify_action.update_external_removed ] = 'update_external_removed'
            self.wc_notify_action_map[ pysvn.wc_notify_action.update_shadowed_add ] = 'update_shadowed_add'
            self.wc_notify_action_map[ pysvn.wc_notify_action.update_shadowed_update ] = 'update_shadowed_update'
            self.wc_notify_action_map[ pysvn.wc_notify_action.update_shadowed_delete ] = 'update_shadowed_delete'
            self.wc_notify_action_map[ pysvn.wc_notify_action.merge_record_info ] = 'merge_record_info'
            self.wc_notify_action_map[ pysvn.wc_notify_action.upgraded_path ] = 'upgraded_path'
            self.wc_notify_action_map[ pysvn.wc_notify_action.merge_record_info_begin ] = 'merge_record_info_begin'
            self.wc_notify_action_map[ pysvn.wc_notify_action.merge_elide_info ] = 'merge_elide_info'
            self.wc_notify_action_map[ pysvn.wc_notify_action.patch ] = 'patch'
            self.wc_notify_action_map[ pysvn.wc_notify_action.patch_applied_hunk ] = 'patch_applied_hunk'
            self.wc_notify_action_map[ pysvn.wc_notify_action.patch_rejected_hunk ] = 'patch_rejected_hunk'
            self.wc_notify_action_map[ pysvn.wc_notify_action.patch_hunk_already_applied ] = 'patch_hunk_already_applied'
            self.wc_notify_action_map[ pysvn.wc_notify_action.commit_copied ] = 'commit_copied'
            self.wc_notify_action_map[ pysvn.wc_notify_action.commit_copied_replaced ] = 'commit_copied_replaced'
            self.wc_notify_action_map[ pysvn.wc_notify_action.url_redirect ] = 'url_redirect'
            self.wc_notify_action_map[ pysvn.wc_notify_action.path_nonexistent ] = 'path_nonexistent'
            self.wc_notify_action_map[ pysvn.wc_notify_action.exclude ] = 'exclude'
            self.wc_notify_action_map[ pysvn.wc_notify_action.failed_conflict ] = 'failed_conflict'
            self.wc_notify_action_map[ pysvn.wc_notify_action.failed_missing ] = 'failed_missing'
            self.wc_notify_action_map[ pysvn.wc_notify_action.failed_out_of_date ] = 'failed_out_of_date'
            self.wc_notify_action_map[ pysvn.wc_notify_action.failed_no_parent ] = 'failed_no_parent'

    # SVN Callbacks
    def ssl_server_trust_prompt( self, trust_dict ):
        return True, 1, False

    def get_login( self, realm, username, may_save ):
        username = self.username
        password = self.password
        return True, username, password, False

    def set_conflict_solver(self, f):
        self.solver_helper = f

    def callback_notify( self, arg_dict ):
        if arg_dict['path'] != '' and arg_dict['action'] in self.wc_notify_action_map.keys() and self.wc_notify_action_map[ arg_dict['action'] ] is not None:
            msg = '[svn] %s %s' % (self.wc_notify_action_map[ arg_dict['action'] ], arg_dict['path'])
            print( msg )
            if self.wc_notify_action_map[ arg_dict['action'] ] in ['U', 'A', 'M', 'R', 'c', 'C']:
                filename, fileext = os.path.splitext(os.path.basename(arg_dict['path']))
                self.updated_files.append((filename, fileext, arg_dict['path']))
            if self.wc_notify_action_map[ arg_dict['action'] ] == 'D':
                os.unlink(arg_dict['path'])

    def callback_get_log_message(self):
        # TODO: Check if we need to use this callback for something important,
        #       it's required by checkin (commit) when commit the message is empty.
        return True, "look!, a string!"

    def get_revision(self, path=""):
        #print "getting info for", self.local_dir + path
        #print "number:",  self.svn_client.info(self.local_dir + path).revision.number
        return self.svn_client.info(self.local_dir + path).revision

    def callback_conflict_resolver( self, arg_dict ):
        print "[ ] Solving conflicts"
        if hasattr( types, 'StringTypes' ):
            StringTypes = types.StringTypes
        else:
            StringTypes = [type( '' )]

        if arg_dict['my_file'] and arg_dict['their_file']:
            try:
                self.solver_helper([arg_dict['my_file'], arg_dict['their_file']])
            except:
                import sys, traceback
                print "Exception in user code:"
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60
                print "[-] Cannot merge files. Postpone."
                return pysvn.wc_conflict_choice.postpone, None, False
                #with open(arg_dict['my_file']) as fh:
                #    data = fh.read()
                #self.svn_client.revert(arg_dict['path'])
                #fh = open(arg_dict['my_file'], "w")
                #fh.write(data)
                #fh.close()


        # for key in sorted( arg_dict.keys() ):
        #     value = arg_dict[ key ]
        #     if type(value) not in StringTypes:
        #         value = repr(value)
        #     print( '[svn]  %s: %s' % (key, value) )

        # not really mine_full, solve_helper createst a filename.solved.dat,
        # which is later renamed to filename.dat in the gui, because
        # pysvn replaces the solved file in other case...
        return pysvn.wc_conflict_choice.mine_full, None, False

    def commit(self, files, message=""):
        self.svn_client.callback_get_log_message = self.callback_get_log_message
        self.svn_client.checkin(files, message)

    def update(self):
        self.updated_files = []
        #self.svn_client.unlock(self.local_dir)
        rev = self.svn_client.update(self.local_dir)
        return rev, self.updated_files

    def checkout(self):
        self.svn_client.checkout(self.rep_url, self.local_dir)

    def add(self, filename):
        self.svn_client.add(filename)

    def is_working_copy(self, path):
        if not path.endswith(os.sep):
            path += os.sep
        return os.path.exists(path + ".svn")

    def files_to_commit(self):
        try:
            changes = self.svn_client.status(self.local_dir)
            added = [("A", f.path) for f in changes if f.text_status == pysvn.wc_status_kind.added]
            deleted = [("D", f.path) for f in changes if f.text_status == pysvn.wc_status_kind.deleted]
            modified = [("M", f.path) for f in changes if f.text_status == pysvn.wc_status_kind.modified]        
            unversioned = [("U", f.path) for f in changes if f.text_status == pysvn.wc_status_kind.unversioned]        
            return added + deleted + modified + unversioned
        except pysvn.ClientError:
            dat_files = [("U", self.local_dir + os.sep + each_file) for each_file in os.listdir(self.local_dir) if ".dat" in each_file]
            return dat_files


