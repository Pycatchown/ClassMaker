import idaapi
import ida_funcs
import idc
import ida_kernwin
import ida_hexrays
import ida_lines
import ida_typeinf
import re
import uuid

IS_64 = idaapi.get_inf_structure().is_64bit()
SIZEOF_PTR = 8 if IS_64 else 4

def read_ptr(ea):
    if IS_64:
        return idaapi.get_qword(ea)
    return idaapi.get_dword(ea)

def get_type(size):
    if size == 1:
        return "byte"
    elif size == 2:
        return "word"
    elif size == 4:
        return "dword"
    elif size == 8:
        return "qword"

def get_idasize_from_size(size):
    if size == 1:
        return idaapi.FF_BYTE
    elif size == 2:
        return idaapi.FF_WORD
    elif size == 4:
        return idaapi.FF_DWORD
    elif size == 8:
        return idaapi.FF_QWORD
    else:
        return idaapi.DT_TYPE

def pretty(insn):
    print(f"{insn.ea:x}: {insn.opname}")


class ClassConstructor(ida_hexrays.ctree_visitor_t):

    def __init__(self, idx = 0, struct = {}):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        self.idx = idx
        self.name_class = ""
        self.struct = struct

    def visit_insn(self, ins):
        if ins.cexpr:
            #self.dump_cexpr(ins.cexpr.ea, ins.cexpr)
            if ins.cexpr.op == ida_hexrays.cot_asg:
                self.build_struct_fromasg(ins.cexpr)
            elif ins.cexpr.op == ida_hexrays.cot_call:
                pass#self.build_struct_fromcall(ins.cexpr)
                
        return 0
    
    def make_vftable(self, vftable):
        vftable_struct_id = idaapi.get_struc_id(vftable["name"])
        if vftable_struct_id == idaapi.BADADDR:
            vftable_struct_id = idc.add_struc(0, vftable["name"], 0)
        if vftable_struct_id == idaapi.BADADDR:
            print(vftable)
        for i in range(len(vftable["methods"])):
            idc.add_struc_member(vftable_struct_id, vftable["methods"][i]["name_func"], i * SIZEOF_PTR, get_idasize_from_size(SIZEOF_PTR), -1, SIZEOF_PTR)
            proto = idc.get_type(vftable['methods'][i]['ea_func'])
            if proto == None: #no typing decl
                proto = f"void __thiscall(*{vftable['methods'][i]['name_func']})({self.name_class} *this)"
            else:
                p = proto.split("(")
                print(p)
                p[0] += f" (*{vftable['methods'][i]['name_func']})"
                args = p[1].split(',')
                args[0] = f"{self.name_class} *{')' if len(args) == 1 else ''}"
                p[1] = ",".join(args)
                proto = "(".join(p)
                idc.SetType(vftable['methods'][i]['ea_func'], proto)
            idc.SetType(idc.get_member_id(vftable_struct_id, i * SIZEOF_PTR), proto)
        return vftable_struct_id

    def make_class_idastruct(self):
        if self.name_class == "":
            self.name_class = ida_kernwin.ask_str("", 0, "Unfortunately, the class name couldn't be determined, please enter a class name:")
        if self.name_class == None:
            print("Couldn't determine class name")
            return
        self.ida_struct_id = idaapi.get_struc_id(self.name_class)
        if self.ida_struct_id == idaapi.BADADDR:
            self.ida_struct_id = idc.add_struc(0, self.name_class, 0)
            if self.ida_struct_id == idaapi.BADADDR:
                self.name_class += "_"
                self.ida_struct_id = idc.add_struc(0, self.name_class, 0)
        print(hex(self.ida_struct_id))
        for k, v in self.struct.items():
            idc.add_struc_member(self.ida_struct_id, v["name"], k, get_idasize_from_size(v["size"]), -1, v["size"])
            if (vftable := v.get("vftable")) is not None:
                vftable_id = self.make_vftable(vftable)
                idc.SetType(idc.get_member_id(self.ida_struct_id, k), f'struct {vftable["name"]} *')
    
    def get_methods_from_vtable(self, ea):
        if ea == idaapi.BADADDR:
            return None
        methods = []
        while ((addr := read_ptr(ea)) != idaapi.BADADDR):
            f = ida_funcs.get_func(addr)
            if f == None or addr != f.start_ea:
                break
            name_func = idaapi.get_ea_name(addr, idaapi.GN_SHORT|idaapi.GN_DEMANGLED).split("(")[0].replace("::", "__").replace("<", "_").replace(">", "_")
            name_func = re.sub(r"[^a-zA-Z0-9\_]+",'', name_func)
            methods += [{"ea_func":addr, "name_func": name_func}]
            ea += SIZEOF_PTR
        return methods

    def add_struct_member(self, cexpr, offset, refwidth):
        if (cexpr.y and cexpr.y.op == ida_hexrays.cot_ref) or (cexpr.y and cexpr.y.op == ida_hexrays.cot_add and cexpr.y.x.op == ida_hexrays.cot_ref):
            to_add = 0
            if cexpr.y.op == ida_hexrays.cot_add:
                ref = cexpr.y.x
                to_add = cexpr.y.y.numval() *  SIZEOF_PTR
            else:
                ref = cexpr.y
            methods = self.get_methods_from_vtable(ref.x.obj_ea + to_add) # TODO: being careful in case of other refs in class that arn't vtables
            name_vtable = "v" + str(uuid.uuid4()).split('-')[0]
            while idaapi.get_struc_id(name_vtable) != idaapi.BADADDR:
                name_vtable = "v" + str(uuid.uuid4()).split('-')[0]
            self.struct[offset] = {"name": f"vt{offset}", "size": refwidth, "vftable": {"ea": cexpr.y.x.obj_ea + to_add, "name": f"{name_vtable}", "methods": methods}}
            if offset == 0:
                self.name_class = idaapi.get_ea_name(ref.x.obj_ea, idaapi.GN_SHORT|idaapi.GN_DEMANGLED)
                self.name_class = re.sub(r"\`.*'",'',  self.name_class).split(" ")[-1:][0]
                if self.name_class.endswith("::"):
                    self.name_class = self.name_class[:-2]

        else:
            self.struct[offset] = {"name": f"{get_type(refwidth)}{offset}", "size": refwidth}

    def build_struct_fromcall(self, cexpr):
        for arg in cexpr.a:
            if arg.op == ida_hexrays.cot_add:
                if (v := arg.x.find_op(ida_hexrays.cot_var)):
                    print(v)
                    if v.v.idx == self.idx:
                        self.add_struct_member(arg, arg.y.numval(), SIZEOF_PTR)


    def build_struct_fromasg(self, cexpr):
        try:
            if cexpr.x:
                if cexpr.x.op == ida_hexrays.cot_memptr:
                    op_idx = cexpr.x.get_ptr_or_array().v.idx
                    if op_idx != self.idx:
                        return
                    self.add_struct_member(cexpr, cexpr.x.m,  cexpr.x.refwidth)
                elif cexpr.x.op == ida_hexrays.cot_ptr:
                    cast = cexpr.x.get_ptr_or_array()
                    if cast.op  == ida_hexrays.cot_var:
                        if cast.v.idx != self.idx:
                            return
                        self.add_struct_member(cexpr, 0, cexpr.x.refwidth)
                    elif cast.x.op == ida_hexrays.cot_var:
                        if cast.x.v.idx != self.idx:
                            return
                        self.add_struct_member(cexpr, 0, cexpr.x.refwidth)
                    elif cast.x.op == ida_hexrays.cot_add:
                        if cast.x.x.op == ida_hexrays.cot_cast:
                            if cast.x.x.x.v.idx != self.idx:
                                return
                            self.add_struct_member(cexpr, cast.x.y.numval(), cexpr.x.refwidth)
                        else:
                            if cast.x.x.v.idx != self.idx:
                                return
                            self.add_struct_member(cexpr, cast.x.y.numval(), cexpr.x.refwidth)
                    elif cast.x.op == ida_hexrays.cot_cast:
                        if cast.x.x.v == None or cast.x.x.v.idx != self.idx:
                            return
                        self.add_struct_member(cexpr, cast.y.numval() * cexpr.x.refwidth, cexpr.x.refwidth)
        except:
            print(f"error at {cexpr.ea:x}, {cexpr.x.opname}")

    def dump_cexpr(self, ea, cexpr):
        # iterate over all block instructions
        print("dumping cexpr %x: %s" % (ea, cexpr.opname,))
        if cexpr.x:
            if cexpr.x.op == ida_hexrays.cot_idx:
                print(f"  {cexpr.ea:x}: op {cexpr.x.opname} (var: v{cexpr.x.opname})")
            elif cexpr.x.op == ida_hexrays.cot_var:
                print("  %x: op %s (var: v%d)" % (cexpr.x.ea, cexpr.x.opname, cexpr.x.v.idx))
            elif cexpr.x.op == ida_hexrays.cot_memptr:
                print("  %x: op %s (var: v%d+%d)" % (cexpr.x.ea, cexpr.x.opname, cexpr.x.get_ptr_or_array().v.idx, cexpr.x.m))
            elif cexpr.x.op == ida_hexrays.cot_ptr:
                ptr = cexpr.x.get_ptr_or_array()
                print(ptr.opname)
                if ptr.op  == ida_hexrays.cot_var:
                    print(f"  {cexpr.ea:x}: op {cexpr.opname} (var: v{ptr.v.idx})")
                elif ptr.x.op == ida_hexrays.cot_var:
                    print(f"  {cexpr.x.ea:x}: op {cexpr.x.opname} (var: v{ptr.x.v.idx})")
                elif ptr.x.op == ida_hexrays.cot_add:
                    print(f"  {cexpr.x.ea:x}: op {cexpr.x.opname} (var: v{ptr.x.x.v.idx}+{ptr.x.y.numval()})")
                #print("  %x: op %s (var: v%d+%d)" % (cexpr.x.ea, cexpr.x.opname, cexpr.x.get_ptr_or_array().v.idx, cexpr.x.m))
            else:
                print("  %x: unknown x op %s" % (cexpr.x.ea, cexpr.x.opname))
        if cexpr.y:
            if cexpr.y.op == ida_hexrays.cot_num:
                print("  %x: op %s (num: 0x%x)" % (cexpr.y.ea, cexpr.y.opname, cexpr.y.numval()))
            else:
                print("  %x: unknown y op %s" % (cexpr.y.ea, cexpr.y.opname))
        if cexpr.z:
            print("THE OPERAND I HAVE NO CLUE WHAT'S ITS PURPOSE AND NEITHER DO THE DOC : Z FOUND!!!! %x: op %s" % (cexpr.z.ea, cexpr.z.opname))



def make_class(ea, idx_choosed):
    if ida_hexrays.init_hexrays_plugin():
        idx_choosed = idx_choosed
        x = ClassConstructor(idx = idx_choosed, struct = {})
        f = ida_funcs.get_func(ea)
        cfunc = ida_hexrays.decompile(f)

        tif = idaapi.tinfo_t()
        tif.get_named_type(idaapi.get_idati(), "_QWORD" if IS_64 else "_DWORD")
        tif.create_ptr(tif)
        lst = ida_hexrays.lvar_saved_info_t()
        lst.ll = cfunc.lvars[idx_choosed]
        lst.type = ida_typeinf.tinfo_t(tif)
        ida_hexrays.modify_user_lvar_info(f.start_ea, ida_hexrays.MLI_TYPE, lst)
        cfunc = ida_hexrays.decompile(f)

        x.apply_to(cfunc.body, None)
        print(x.struct)

        x.make_class_idastruct()

        tif = idaapi.tinfo_t()
        tif.get_named_type(idaapi.get_idati(), x.name_class)
        tif.create_ptr(tif)
        lst = ida_hexrays.lvar_saved_info_t()
        lst.ll = cfunc.lvars[idx_choosed]
        lst.type = ida_typeinf.tinfo_t(tif)
        ida_hexrays.rename_lvar(f.start_ea, cfunc.lvars[idx_choosed].name, "v_" + x.name_class)
        ida_hexrays.modify_user_lvar_info(f.start_ea, ida_hexrays.MLI_TYPE, lst)
        cfunc = ida_hexrays.decompile(f)
        cfunc.refresh_func_ctext()
        #idc.SetType(0, f'struct {x.name_class} *')
    else:
        print('error')

class CexprFinder(ida_hexrays.ctree_visitor_t):

    def __init__(self, ea):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        self.ea = ea
        self.result = None

    def visit_insn(self, ins):
        if ins.cexpr:
            if self.result is None and ins.cexpr.ea == self.ea:
                self.result = ins.cexpr
        return 0

class MakeClassHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        print("activated")
        if ctx.cur_ea == idaapi.BADADDR:
            print("bad ea")
            return 1
        
        cfunc = ida_hexrays.decompile(ctx.cur_ea)
        finder = CexprFinder(ctx.cur_ea)
        finder.apply_to(cfunc.body, None)
        cexpr = finder.result
        if cexpr == None:
            print(f"Cursor is not placed at a vtable, couldn't find cexpr at {ctx.cur_ea:x}")
            return 1

        idx = -1
        if cexpr.x and cexpr.x.op == ida_hexrays.cot_memptr:
                idx = cexpr.x.get_ptr_or_array().v.idx
        elif cexpr.x and cexpr.x.op == ida_hexrays.cot_ptr:
                cast = cexpr.x.get_ptr_or_array()
                if cast.op  == ida_hexrays.cot_var:
                    idx = cast.v.idx
                elif cast.x.op == ida_hexrays.cot_var:
                    idx = cast.x.v.idx
                elif cast.x.op == ida_hexrays.cot_add:
                    idx = cast.x.x.v.idx
                elif cast.x.op == ida_hexrays.cot_cast:
                    idx = cast.x.x.v.idx
        
        if idx == -1:
            print("Couldn't find the variable that points to the class")
            return 1
        make_class(ctx.cur_ea, idx)
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

action_desc = idaapi.action_desc_t(
    'make:class',
    'Create a class',
    MakeClassHandler(),
    '4',
    'Make a class'
)
idaapi.unregister_action('make:class')
idaapi.register_action(action_desc)