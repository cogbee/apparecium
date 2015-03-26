#!/usr/bin/env python
import sys
import os
import time
import collections
import re

from androguard.core import bytecode
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis.ganalysis import GVMAnalysis
from androguard.core.analysis.analysis import uVMAnalysis
from stopwatch import Stopwatch

import pdb
pdb.set_trace()

#our config
import config

def fun2():
    return collections.defaultdict(list)
def fun():
    return collections.defaultdict(fun2)

#EXTERNAL_TUNNEL_ - TO STORE READS & WRITES FROM/TO EXTERNAL SOURCES (Files, DB, SharedPreferences, Sockets)
STREAMS_WRITE = []
STREAMS_READ = []
#EXTERNAL_TUNNEL_2 - TO STORE SENT / RECEIVED INTENTS
INTENTS_READ = []
INTENTS_WRITE = []
#EXTERNAL_TUNNEL_4 - TO STORE SENT INTENTS THROUGH BROADCAST RECEIVER (they are received in the onReceive() method)
INTENTS_BROADCAST_SENT = []
#EXTERNAL_TUNNEL_4 - TO STORE THE [key,pc] OF THE FIRST LINE OF THE onReceive(Intent) method
FIRST_LINE_ONRECEIVE = []
#EXTERNAL_TUNNEL_5 - TO STORE CONTENT PROVIDERS INSERTS AND QUERIES
CONTENT_PROV_WRITE = []
CONTENT_PROV_READ = []
def parse_methods(infile, search_source, search_sink):
    METHODS = {}
    MEMBERS = collections.defaultdict(lambda: collections.defaultdict(list)) # hash of hash to list
    SOURCES = []
    SINKS = []
    
    STREAMS_WRITE = []
    STREAMS_READ = []
    INTENTS_READ = []
    INTENTS_WRITE = []
    INTENTS_BROADCAST_SENT = []
    FIRST_LINE_ONRECEIVE = []
    CONTENT_PROV_WRITE = []
    CONTENT_PROV_READ = []
    
    #create system METHOD's code
#     framework_dex = []#'./framework/core.dex']
#     for f in framework_dex:
#         #print "Parsing %s" % f
#         
#         new_methods = {}
#         d = DalvikVMFormat(open(f, 'rb').read())
#         dx = analysis.VMAnalysis(d)
#         for current_method in dx.get_methods():
#             key = '%s %s %s' % (current_method.method.get_class_name(), current_method.method.get_name(), current_method.method.get_descriptor())
#             #create bb-graphs
#             #bytecode.method2png('/home/user/projects/android-instrumentation/methods/'+key.replace('/', '.')+'.png', current_method)
#             line = 0
#             pc = 0
#             line_to_pc = {}
#             if current_method.method.get_code() is not None:
#                 for ins in current_method.method.get_code().get_bc().get_instructions():
#                     line_to_pc[line] = [pc, ins]
#                     pc += ins.get_length()
#                     line += 1
#             new_methods[key] = [current_method, line_to_pc]
#                     
#         METHODS.update(new_methods)
        
    my_apk = apk.APK(infile)
    dex = DalvikVMFormat(my_apk.get_dex())
    dex.create_python_export()
    dx = uVMAnalysis(dex)
    gx = GVMAnalysis(dx, my_apk)
    dex.set_vmanalysis(dx)
    dex.set_gvmanalysis(gx)
    dex.create_xref()

    #print "Generating Methods for %s" % input
    for current_method in dx.get_methods():
        key = '%s %s %s' % (current_method.method.get_class_name(), current_method.method.get_name(), current_method.method.get_descriptor())
        #OUTPUT method name
        #print "\n", key
        #create bb-graphs
        #bytecode.method2png('/home/user/projects/android-instrumentation/methods/'+key.replace('/', '.')+'.png', current_method)
        line = 0
        pc = 0
        line_to_pc = {}
        pc_to_line = {}
        out_bb = []
        if current_method.method.get_code() is not None:

            # callbacks
            if config.ENABLE_EXTERNAL_PATHS:
                if ('onReceive' in current_method.method.get_name() 
                    and 'Landroid/content/Intent' in current_method.method.proto):
                        FIRST_LINE_ONRECEIVE.append([key,pc])

            for ins in current_method.method.get_code().get_bc().get_instructions():
                if 'invoke' in ins.get_name():
                    if config.ENABLE_EXTERNAL_PATHS:
                        function = ins.get_output(pc).split(', ')[-1];
                        #EXTERNAL_TUNNEL_8 - Fixed PrintWriter issues : it also has write, and println may also be relevant 
                        if ('java/io/PrintWriter;->print' in function 
                            or 'java/io/PrintWriter;->write' in function 
                            or 'java/io/OutputStream;->write' in function
                            or 'java/io/ByteArrayOutputStream;->write' in function
                            or 'java/io/DataOutputStream;->write' in function
                            or 'java/io/FileOutputStream;->write' in function
                            or 'java/util/zip/GZIPInputStream;->write' in function
                            or 'java/io/BufferedOutputStream;->write' in function
                            or 'java/io/OutputStreamWriter;->write' in function
                            or 'java/io/FileWriter;->write' in function
    # EXTERNAL_TUNNEL_9 - This works but it is too generic                       or 'java/io/Writer;->write' in function  
                            or 'android/content/SharedPreferences$Editor;->put' in function 
                            or 'android/database/sqlite/SQLiteDatabase;->insert' in function):
                            STREAMS_READ.append([key,pc])
    # EXTERNAL_TUNNEL_7 - Improved class specification to avoid unexpected, app-specific method calls                      
                        elif ('java/io/InputStream;->read' in function
                            or 'java/io/BufferedInputStream;->read' in function
                            or 'java/io/ByteArrayInputStream;->read' in function
                            or 'java/io/DataInputStream;->read' in function
                            or 'java/io/FileInputStream;->read' in function
                            or 'java/io/InputStreamReader;->read' in function
                            or 'java/util/zip/GZIPOutputStream;->read' in function
                            or 'java/io/BufferedReader;->read' in function
                            or 'java/io/FileReader;->read' in function
    # EXTERNAL_TUNNEL_9 - This works but it is too generic                        or 'java/io/Reader;->read' in function                         
                            or 'android/content/SharedPreferences;->get' in function 
                            or 'android/database/sqlite/SQLiteDatabase;->query' in function):
                                STREAMS_WRITE.append([key,pc])
                        #EXTERNAL_TUNNEL_2 - to address leakage through intents
                        #EXTERNAL_TUNNEL_3 - Bugfix to avoid startActivity methods that do not receive an intent
                        #EXTERNAL_TUNNEL_8 - Bugfix to avoid static startActivity methods (they are not from Context)- protection also added in sendBroadcast  
                        elif ('startActivity' in function and 'Landroid/content/Intent' in function # TODO fix
                            and not 'makeRestartActivity' in function):
                                INTENTS_WRITE.append([key,pc])
                        elif ('getIntent' in function):
                            INTENTS_READ.append([key,pc])
                        #EXTERNAL_TUNNEL_4 - Use of broadcast receivers to send intents  
                        elif ('sendBroadcast' in function # TODO: Fix
                            and 'Landroid/content/Intent' in function):
                                INTENTS_BROADCAST_SENT.append([key,pc])      
                        #EXTERNAL_TUNNEL_5 - Use of content providers
                        #EXTERNAL_TUNNEL_8 - Code rewriting to make it easier to understand
                        elif 'android/content/ContentResolver;->insert' in function:
                            CONTENT_PROV_WRITE.append([key,pc])
                        elif 'android/content/ContentResolver;->query' in function:
                            CONTENT_PROV_READ.append([key,pc])
                    # ENDIF config.ENABLE_EXTERNAL_PATHS
                    
                    if [i for i in search_source if i in ins.get_output(pc)]:
                        SOURCES.append([key, pc])
                    if [i for i in search_sink if i in ins.get_output(pc)]:
                        SINKS.append([key, pc])
                        
                if 'return-wide' in ins.get_name():
                    out_bb.append([pc, [ins.get_output(), 'v'+str(int(ins.get_output().replace('v', ''))+1)]])
                elif 'return-void' in ins.get_name():
                    out_bb.append([pc, []])
                elif 'return' in ins.get_name():
                    out_bb.append([pc, [ins.get_output()]])
                    
                if 'sput' in ins.get_name() or 'iput' in ins.get_name():
                    var_name = ins.get_output().split(', ')[-1]
                    MEMBERS[var_name]['write'].append([key, pc])
                        
                if 'sget' in ins.get_name() or 'iget' in ins.get_name():
                    var_name = ins.get_output().split(', ')[-1]
                    MEMBERS[var_name]['read'].append([key, pc])
                
                bb = None
                for block in current_method.basic_blocks.bb:
                    if block.start <= pc < block.end:
                        bb = block
                    
                line_to_pc[line] = [pc, ins]
                pc_to_line[pc] = [line, ins, bb]
#                 print line, pc, ins.get_name(), ins.get_output(pc)
                pc += ins.get_length()
                line += 1
        METHODS[key] = [current_method, line_to_pc, out_bb, pc_to_line]
        
    print "\t%d methods parsed (size: %.2fkB)" % (len(METHODS), float(sys.getsizeof(METHODS))/1024)
    return METHODS, MEMBERS, SOURCES, SINKS, dex
    
def dfg_forward(METHODS, MEMBERS, SOURCES, dex):
    MARKED_VARS = collections.defaultdict(lambda: collections.defaultdict(list)) # hash from node to pc to marked variables
    MARKED_MEMBERS = []
    investigated_functions = []
    
    class FA_WorklistEntry:
        def __init__(self, function, pc, callstack):
            self.function = function
            self.pc = pc
            self.callstack = callstack
        
        def __eq__(self, other): 
            return (self.function == other.function and\
                    self.pc == other.pc and\
                    self.callstack == other.callstack) 
    
    TODO_INSTRUCTIONS = []
    for source in SOURCES:
        TODO_INSTRUCTIONS.append(FA_WorklistEntry(source[0], source[1], []))
        
    current_calculating_nodes = [i.function for i in TODO_INSTRUCTIONS]

    first_run = True #for the first run, we have to add all variables to the marked vars!
    while TODO_INSTRUCTIONS:
        cnt_fun = []
#         for i in TODO_INSTRUCTIONS:
#             if i.function not in cnt_fun:
#                 cnt_fun.append(i.function)
#         print "Functions: %d, Instructions: %d" % (len(cnt_fun), len(TODO_INSTRUCTIONS))
        
#         if len(cnt_fun) > 600:
#             import code
#             code.interact(local=locals())
            
        NEXT_TODO = []
        #handle all blocks + function calls, before stepping one function down
        todo = []
        for i in TODO_INSTRUCTIONS:     
            if i.function in current_calculating_nodes:
                todo.append(i)
            else:
                NEXT_TODO.append(i)
        if not todo:
            NEXT_TODO = []
            current_calculating_nodes = [TODO_INSTRUCTIONS[0].function]
            continue
        
        # investigate lowest pcs first
        todo = sorted(todo, key=lambda i: i.pc, reverse=False)
        
        if first_run:
            for ins in todo:
                current_function = ins.function
                pc = ins.pc
                pc, instruction = get_next_instruction_and_pc(current_function, pc, METHODS)

                if 'move-' in instruction.get_name():
                    variables = instruction.get_output().split(', ')
                    if '-wide' in instruction.get_name():
                        variables.append('v' + str(int(variables[0].replace('v', ''))+1))
                    MARKED_VARS[current_function][pc].extend(variables)
                    NEXT_TODO.append(FA_WorklistEntry(current_function, pc, []))
                #print "(%s) 0x%x" % (current_function, pc), instruction.get_name(), instruction.get_output()
                
            first_run = False
            TODO_INSTRUCTIONS = []
            for e in NEXT_TODO:
                if e not in TODO_INSTRUCTIONS: #more complex test, unhashable -> list(set( not available
                    TODO_INSTRUCTIONS.append(e)
        else:
            for ins in todo:
                current_function = ins.function     
                pc = ins.pc
                instruction = get_instruction(current_function, pc, METHODS)
                    
#                 print "(%s) 0x%x %s %s [%s]" % (current_function, pc, instruction.get_name(), instruction.get_output(), ", ".join(MARKED_VARS[current_function][pc]))
#                 if 'getUrl' in current_function:
#                     print "stop"

                if ('goto' in instruction.get_name()
                        or 'if' in instruction.get_name() 
                        or 'throw' in instruction.get_name()
                        or 'packed-switch' in instruction.get_name()
                    ):
                    block = get_block(METHODS, current_function, pc)
                    line = pc_to_line(current_function, pc, METHODS)
                    next_pc = []
                    for pre in block.childs: #there will/should be only one child
                        child = pre[2]
                        next_pc.append(child.start)
                    if 'throw' in instruction.get_name():
                        if block.exception_analysis:
                            for ex in block.exception_analysis.exceptions:
                                next_pc.append(ex[1]) # ex[1] = next pc
                    if 'if' in instruction.get_name():
                        next_pc.append(METHODS[current_function][1][line+1][0]) #next pc
                    next_pc = unique(next_pc)
                    for nex in next_pc:
                        if update_vars_if_not_equal(MARKED_VARS, MARKED_VARS[current_function][pc], current_function, nex):
                            NEXT_TODO.append(FA_WorklistEntry(current_function, nex, ins.callstack))
                    continue

                if 'return' in instruction.get_name():
                    variables = instruction.get_output().split(', ')
                    if '-wide' in instruction.get_name():
                        variables.append('v' + str(int(variables[0].replace('v', ''))+1))
                    if ins.callstack:
                        # if return tainted-> taint move-result of parent (in ins.callstack)
                        if [i for i in MARKED_VARS[current_function][pc] if i in variables]:
                            #jump back to function and mark assigned variables
                            new_marked = []
                            callee = ins.callstack[-1]
                            callee_callee = ins.callstack[:-1]
                            callee_function = callee[0]
                            callee_pc = callee[1]
                            instruction = pc_to_instruction(callee_function, callee_pc, METHODS)
                            if 'static' not in instruction.get_name():
                                mi = get_method_info(METHODS[current_function][0].method)
                                instance_var = 'v%d' % mi['registers'][1]
                                variables = get_variables_from_invoke(instruction)

                                this_var = variables[0]
                                if instance_var in MARKED_VARS[current_function][0]:
                                    if this_var not in set(MARKED_VARS[callee_function][callee_pc]):
                                        MARKED_VARS[callee_function][callee_pc].append(this_var)
                                        new_marked.append(this_var)
                                else:
                                    if this_var in set(MARKED_VARS[callee_function][callee_pc]):
                                        MARKED_VARS[callee_function][callee_pc].remove(this_var)                                    
                                
                            callee_next_pc = get_next_pc(callee_function, callee_pc, METHODS)
                            next_instruction = pc_to_instruction(callee_function, callee_next_pc, METHODS)
                            #print "Jumping back to %s %d:" % (callee_function, callee_pc), instruction.get_name(), instruction.get_output()
                            if 'move-' in next_instruction.get_name():
                                new_marked.extend(next_instruction.get_output().split(', '))
                                if '-wide' in next_instruction.get_name():
                                    new_marked.append('v' + str(int(new_marked[0].replace('v', ''))+1))
                                if update_vars_if_not_equal(MARKED_VARS, new_marked, callee_function, callee_next_pc):
                                    NEXT_TODO.append(FA_WorklistEntry(callee_function, callee_next_pc, callee_callee))
                    else: # if the return is tainted, and no callstack is set, jump to ALL calling functions
                        if [i for i in MARKED_VARS[current_function][pc] if i in variables]:
                            print "we are now in " + current_function
                            new_marked = []
                            for parent in METHODS[current_function][0].method.XREFfrom.items:
                                parent_key = '%s %s %s' % (parent[0].get_class_name(), parent[0].get_name(), parent[0].get_descriptor())
                                print "Returning to " + parent_key
                                for entry in parent[1]:
                                    parent_next_pc = get_next_pc(parent_key, entry.idx, METHODS)
                                    next_instruction = pc_to_instruction(parent_key, parent_next_pc, METHODS)
                                    if 'move-' in next_instruction.get_name():
                                        new_marked.extend(next_instruction.get_output().split(', '))
                                        if '-wide' in next_instruction.get_name():
                                            new_marked.append('v' + str(int(new_marked[0].replace('v', ''))+1))
                                        if update_vars_if_not_equal(MARKED_VARS, new_marked, parent_key, parent_next_pc):
                                            NEXT_TODO.append(FA_WorklistEntry(parent_key, parent_next_pc, []))
                    continue

                next_pc = get_next_pc(current_function, pc, METHODS)
                
                if instruction.get_name() == 'move-exception':
                    target = instruction.get_output().split(', ')[0]
                    for bb in METHODS[current_function][0].basic_blocks.bb:
                        if bb.exception_analysis:
                            for ex in bb.exception_analysis.exceptions:
                                if pc == ex[1]:
                                    prev_pc = bb.end - bb.last_length
                                    variables_last = get_instruction(current_function, prev_pc, METHODS).get_output().split(', ')[0]
                                    new_marked = MARKED_VARS[current_function][pc]
                                    if variables_last in MARKED_VARS[current_function][prev_pc] and target not in MARKED_VARS[current_function][pc]:
                                        new_marked.append(target)
                                        
                                    if update_vars_if_not_equal(MARKED_VARS, new_marked, current_function, next_pc):
                                        NEXT_TODO.append(FA_WorklistEntry(current_function, next_pc, ins.callstack))
                
                elif instruction.get_name() in config.UNTAINT or 'iget' in instruction.get_name() or 'sget' in instruction.get_name():
                    variables = instruction.get_output().split(', ')
                    if '-wide' in instruction.get_name():
                        variables.append('v' + str(int(variables[0].replace('v', ''))+1))
                    if 'iget' in instruction.get_name() or 'sget' in instruction.get_name():
                        member_name = variables[-1]
                        if member_name in MARKED_MEMBERS:
                            #this member is already tainted. do not config.untaint
                            variables = []
                        else:
                            variables = [variables[0]]
                    new_marked = [i for i in MARKED_VARS[current_function][pc] if i not in variables]
                    MARKED_VARS[current_function][pc] = new_marked # config.untaint current line
                    if update_vars_if_not_equal(MARKED_VARS, new_marked, current_function, next_pc):
                        NEXT_TODO.append(FA_WorklistEntry(current_function, next_pc, ins.callstack))
                elif instruction.get_name() in config.NOPS or 'move-result' in instruction.get_name():
                        if update_vars_if_not_equal(MARKED_VARS, MARKED_VARS[current_function][pc], current_function, next_pc):
                            NEXT_TODO.append(FA_WorklistEntry(current_function, next_pc, ins.callstack))
                elif instruction.get_name() in config.INSTRUCTION_PROPAGATION:
                    variables = instruction.get_output().split(', ')
                    input_variables = [variables[i] for i in config.INSTRUCTION_PROPAGATION[instruction.get_name()][1]]
                    output_variables = [variables[i] for i in config.INSTRUCTION_PROPAGATION[instruction.get_name()][0]]
                    
                    if 'aget-wide' in instruction.get_name():
                        output_variables.append('v' + str(int(variables[0].replace('v', ''))+1))
                    if 'aput-wide' in instruction.get_name():  
                        input_variables.append('v' + str(int(variables[0].replace('v', ''))+1))
                    vars_nextline = MARKED_VARS[current_function][pc]  
                    if [i for i in MARKED_VARS[current_function][pc] if i in input_variables]:
                        vars_nextline = vars_nextline + output_variables
                    MARKED_VARS[current_function][pc] = vars_nextline # taint current line
                    MARKED_VARS[current_function][pc] = unique(MARKED_VARS[current_function][pc])
                    if update_vars_if_not_equal(MARKED_VARS, vars_nextline, current_function, next_pc):
                        NEXT_TODO.append(FA_WorklistEntry(current_function, next_pc, ins.callstack))
                elif 'iput' in instruction.get_name() or 'sput' in instruction.get_name():
                    temp = instruction.get_output().split(', ')
                    variable = temp[0]
                    member = temp[-1]
                    if variable in MARKED_VARS[current_function][pc]:
                        MARKED_MEMBERS.append(member)
                        MARKED_MEMBERS = unique(MARKED_MEMBERS)
                        if MEMBERS.get(member) and MEMBERS[member].get('read'):
                            for ref in MEMBERS[member]['read']:
                                calling_function = ref[0]
                                location = ref[1]
                                instruction_inner = pc_to_instruction(calling_function, location, METHODS)
                                variables_inner = [instruction_inner.get_output().split(', ')[0]] #get var name, remove field name, first entry is the var, second is This
                                if update_vars_if_not_equal(MARKED_VARS, variables_inner, calling_function, location):
                                    NEXT_TODO.append(FA_WorklistEntry(calling_function, location, []))
                    if update_vars_if_not_equal(MARKED_VARS, MARKED_VARS[current_function][pc], current_function, next_pc):
                        NEXT_TODO.append(FA_WorklistEntry(current_function, next_pc, ins.callstack))
                elif 'filled-new-array' in instruction.get_name():
                    MARKED_VARS[current_function][next_pc].extend(MARKED_VARS[current_function][pc])
                    MARKED_VARS[current_function][next_pc] = unique(MARKED_VARS[current_function][next_pc])
                    
                    nins = get_instruction(current_function, next_pc, METHODS)
                    if 'move-result' in nins.get_name():
                        variables = get_variables_from_invoke(instruction)

                        if [i for i in variables if i in MARKED_VARS[current_function][pc]]:
                            next_variables = nins.get_output().split(', ')
                            
                            if 'wide' in nins.get_name():
                                next_variables = [next_variables[0], 'v' + str(int(next_variables[0].replace('v', ''))+1)]
                                
                            MARKED_VARS[current_function][next_pc].extend(next_variables)
                            MARKED_VARS[current_function][next_pc] = unique(next_variables)
                        pc = next_pc
                        next_pc = get_next_pc(current_function, next_pc, METHODS)
                        
                    if update_vars_if_not_equal(MARKED_VARS, MARKED_VARS[current_function][pc], current_function, next_pc):
                        NEXT_TODO.append(FA_WorklistEntry(current_function, next_pc, ins.callstack))      
                    
                elif 'invoke-' in instruction.get_name():
                    temp = instruction.get_output().split(', ')
                    function = temp[-1]
                    variables = get_variables_from_invoke(instruction)
                    
                    instance_tainted = False
                    if 'static' not in instruction.get_name():
                        if variables[0] in MARKED_VARS[current_function][pc]: # instance var
                            instance_tainted = True
                        variables = variables[1:] # removed instance var
                    marked = []
                    for i, var in enumerate(variables):
                        if var in MARKED_VARS[current_function][pc]:
                            marked.append(i)
                    
                    ex = function.split('(')
                    ex2 = ex[0].split('->')
                    fun_name = '%s %s (%s' % (ex2[0], ex2[1], ex[1])
                    
                    if marked or instance_tainted:
                        
                        if fun_name in METHODS and METHODS[fun_name][1].items(): #if the function is abstract, it does not have code
                            mi = get_method_info(METHODS[fun_name][0].method)
                            params = mi.get('params')
                            last_reg = mi.get('registers')[1]
                            propagated=[]
                            for i in range(len(params)):
                                if i in marked:
                                    propagated.append('v%d' % params[i][0])
#                                     # this seems to be an error in Androguard?? a double only uses one internal register.
#                                     # if we have a function with I D I, the params look like:
#                                     # (7, int), (8, double), (9, int)
#                                     # where is double_high gone?
                            if instance_tainted:
                                propagated.append('v%d' % last_reg)
                            if propagated:
                                var_changed = False
                                if update_vars_if_not_equal(MARKED_VARS, propagated, fun_name, -1):
                                    var_changed = True
                                if update_vars_if_not_equal(MARKED_VARS, propagated, fun_name, 0):
                                    var_changed = True
                                if var_changed or fun_name not in investigated_functions:
                                    if fun_name not in investigated_functions:
                                        investigated_functions.append(fun_name)
                                    NEXT_TODO.append(FA_WorklistEntry(fun_name, 0, ins.callstack + [[current_function, pc]]))
                        else:
                            variables = get_variables_from_invoke(instruction)
                            #print "Function %s not found. Assuming all tainted:\n    0x%x %s %s" % (fun_name, pc, instruction.get_name(), instruction.get_output())
                            if 'static' not in instruction.get_name():
                                MARKED_VARS[current_function][pc].append(variables[0]) # just taint instance var!
                                MARKED_VARS[current_function][pc] = unique(MARKED_VARS[current_function][pc])

                                if config.ENABLE_EXTERNAL_PATHS:
                                    #EXTERNAL_TUNNEL_ - TO SOLVE THE LEAKAGE USING INTERMEDIATE WRITE&READ FILES
                                    #EXTERNAL_TUNNEL_3 - Code rewriting. TO SOLVE THE LEAKAGE USING INTERMEDIATE WRITE&READ FILES/SOCKETS/SHAREDPREF/DATABASES
                                    #@todo - is there any better chance to identify the use of sockets? Streams might be used for other purposes...
                                    #EXTERNAL_TUNNEL_4 - removed 'else' clause to make it more compact (suggested by Dennis). Also removed taintedFile/DB...
                                    #EXTERNAL_TUNNEL_7 - Improved the detection of file/socket reads and writes. Added instructions to next_todo only if there is a move-result Removed the next_pc-next_pc addition to next_todo (discovered by Dennis).
                                        
                            
                                    if (('java/io/FileOutputStream; write' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ('java/io/OutputStream; write' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ('java/io/ByteArrayOutputStream; write' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ('java/io/DataOutputStream; write' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ('java/io/BufferedOutputStream; write' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ('java/io/OutputStreamWriter; write' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ('java/io/FileWriter; write' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
    # EXTERNAL_TUNNEL_9 - This works but it is too generic                                    ('java/io/Writer; write' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ('java/util/zip/GZIPOutputStream; write' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ((('java/io/PrintWriter; print' in fun_name and not 'java/io/PrintWriter; printf' in fun_name) 
                                            or 'java/io/PrintWriter; write' in fun_name) and len(variables)>1 and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ('android/database/sqlite/SQLiteDatabase; insert' in fun_name and variables[1] in MARKED_VARS[current_function][pc]) or
                                        ('android/content/SharedPreferences$Editor; put' in fun_name and variables[2] in MARKED_VARS[current_function][pc])):
                                            #print"writing something tainted to external tunnel!"                                                           
                                            for i in STREAMS_WRITE:
                                                current_function_jm = i[0]     
                                                pc_jm = i[1]                                 
                                                instruction_jm = get_instruction(current_function_jm, pc_jm, METHODS)                                                     
                                                temp_jm = instruction_jm.get_output().split(', ')
                                                function_jm = temp_jm[-1]
                                                    
                                                #EXTERNAL_TUNNEL_7 - Bugfix for special read operations. For example, ByteArrayInputStream has a read(byte[],offset,length). We should taint byte[] -- there is no move-result afterwards
                                                #take the variables of the read method and check if it has 4 -- this length only appears in these special read methods
                                                variables_jm = temp_jm[:-1]
                                                if(len(variables_jm) == 4):
                                                    if update_vars_if_not_equal(MARKED_VARS, variables_jm[1], current_function_jm, pc_jm):
                                                        #print"CHECK: instruction %s , fun_name %s , variables %s"%(fun_name,instruction.get_output(), variables)                                                                         
                                                        #print"added the read location to NEXT_TODO, tainting the read result! (len == 4)"
                                                        NEXT_TODO.append(FA_WorklistEntry(current_function_jm, pc_jm, []))
                                                else:
                                                    #these are read operations followed by a move-result    
                                                    #we are addressing read/write through sockets/files. It may lead to false positives (e.g. file write <-> socket read)
                                                    next_pc_jm = get_next_pc(current_function_jm, pc_jm, METHODS)                          
                                                    next_instruction_jm = get_instruction(current_function_jm, next_pc_jm, METHODS)
                                                
                                                    #next_instruction_jm should be move-result-object vX
                                                    variables_next_jm = next_instruction_jm.get_output().split(', ')
                                                    #in variables_next_jm[0] we have the variable storing the line read
                                              
                                                    if('move-result' in next_instruction_jm.get_name()):
                                                        dataRead = variables_next_jm[0]
                                                        if 'wide' in next_instruction_jm.get_name():
                                                            dataRead = [variables_next_jm[0], 'v' + str(int(variables_next_jm[0].replace('v', ''))+1)]
                                                        if update_vars_if_not_equal(MARKED_VARS, dataRead, current_function_jm, next_pc_jm):
                                                            #print"added the read location to NEXT_TODO, tainting the read result!"
                                                            NEXT_TODO.append(FA_WorklistEntry(current_function_jm, next_pc_jm, []))
                                          
                                    #EXTERNAL_TUNNEL_2 - ADDRESSING EXTERNAL INTENTS
                                    elif 'startActivity' in fun_name and 'Landroid/content/Intent' in instruction.get_output():                                   
                                        if (variables[1] in MARKED_VARS[current_function][pc] or
                                           (('FromChild' in fun_name or 'FromFragment' in fun_name ) and variables[2] in MARKED_VARS[current_function][pc])):
                                            for i in INTENTS_READ:
                                                current_function_jm = i[0]     
                                                pc_jm = i[1]
                                                next_pc_jm = get_next_pc(current_function_jm, pc_jm, METHODS)                          
                                                next_instruction_jm = pc_to_instruction(current_function_jm, next_pc_jm, METHODS)
                                                #next_instruction should be move-result-object vX
                                                variables_next_jm = next_instruction_jm.get_output().split(', ')
                                                #in variables[0] we have the variable storing the intent retrieved
                                                if('move-result' in next_instruction_jm.get_name()):
                                                    if update_vars_if_not_equal(MARKED_VARS, variables_next_jm[0], current_function_jm, next_pc_jm):                                                  
                                                        #print "WARNING - SENDING SOMETHING TAINTED THROUGH AN INTENT"                                        
                                                        NEXT_TODO.append(FA_WorklistEntry(current_function_jm, next_pc_jm, []))                                            
                                    #EXTERNAL_TUNNEL_4 - To address intents sent through broadcast receiver
                                    elif 'sendBroadcast' in fun_name and 'Landroid/content/Intent' in instruction.get_output()\
                                        and variables[1] in MARKED_VARS[current_function][pc]:
                                            #we have to append the first line of the onReceive method (there may be more than one!)
                                            for onrcv in FIRST_LINE_ONRECEIVE:
                                                #We would be in the first line of the onReceive method. Taint the received intent if it was tainted
                                                mi = get_method_info(METHODS[onrcv[0]][0].method)
                                                #signature of the method is onReceive(Context, Intent) --> Intent parameter is [1]
                                                #print"list of parameters. . . %s" % (mi['params'][1][0]) 
                                                parameter_intent = 'v%s' % mi['params'][1][0]
                                            
                                                if update_vars_if_not_equal(MARKED_VARS, parameter_intent, onrcv[0], onrcv[1]):                                
                                                    #print "WARNING - SENDING DOMETHING TAINTED THROUGH A BROADCAST"
                                                    #print"parameter_intent %s, marked_vars %s" % (parameter_intent, MARKED_VARS[FIRST_LINE_ONRECEIVE[0][0]][FIRST_LINE_ONRECEIVE[0][1]])
                                                    NEXT_TODO.append(FA_WorklistEntry(onrcv[0],onrcv[1],[]))
                                    #EXTERNAL_TUNNEL_5 - ADDRESSING CONTENT PROVIDERS
                                    elif 'android/content/ContentResolver; insert' in fun_name\
                                        and variables[2] in MARKED_VARS[current_function][pc]:
                                            for i in CONTENT_PROV_READ:
                                                current_function_jm = i[0]     
                                                pc_jm = i[1]
                                                next_pc_jm = get_next_pc(current_function_jm, pc_jm, METHODS)                          
                                                next_instruction_jm = pc_to_instruction(current_function_jm, next_pc_jm, METHODS)
                                                #next_instruction should be move-result-object vX
                                                variables_next_jm = next_instruction_jm.get_output().split(', ')
                                                #in variables[0] we have the variable storing the result of the query
                                                if('move-result' in next_instruction_jm.get_name()):
                                                    if update_vars_if_not_equal(MARKED_VARS, variables_next_jm[0], current_function_jm, next_pc_jm):                                                                
                                                        #print "WARNING - SENDING SOMETHING TAINTED THROUGH A CONTENT PROVIDER"                                        
                                                        NEXT_TODO.append(FA_WorklistEntry(current_function_jm, next_pc_jm, []))   
                                # ENDIF config.ENABLE_EXTERNAL_PATHS

                            next_instruction = pc_to_instruction(current_function, next_pc, METHODS)
                            if 'move-' in next_instruction.get_name():
                                variables_next = next_instruction.get_output().split(', ')
                                if '-wide' in next_instruction.get_name():
                                    v1 = 'v%s' % (str(int(variables_next[0].replace('v', ''))+1))
                                    variables_next += [v1]
                                variables_next = MARKED_VARS[current_function][pc] + variables_next
                                if update_vars_if_not_equal(MARKED_VARS, variables_next, current_function, next_pc):
                                    NEXT_TODO.append(FA_WorklistEntry(current_function, next_pc, ins.callstack))
                    
                                        
                    if update_vars_if_not_equal(MARKED_VARS, MARKED_VARS[current_function][pc], current_function, next_pc):
                        NEXT_TODO.append(FA_WorklistEntry(current_function, next_pc, ins.callstack))
                else:
                    print instruction.get_name(), " not configured!"
                    if update_vars_if_not_equal(MARKED_VARS, MARKED_VARS[current_function][pc], current_function, next_pc):
                        NEXT_TODO.append(FA_WorklistEntry(current_function, next_pc, ins.callstack))
        TODO_INSTRUCTIONS = []
        for e in NEXT_TODO:
            if e not in TODO_INSTRUCTIONS: #more complex test, unhashable -> list(set( not available
                TODO_INSTRUCTIONS.append(e)
        TODO_INSTRUCTIONS = NEXT_TODO
        
    #return infos for smali instrumentation (class, method, instruction nr)
    ret = {}
    #lines = {}
    for m, e in MARKED_VARS.items():
        ret[m]  = {}
        #lines[m] = {}
        for pc, tainted in e.items():
            if pc == -1:
                line_nr = -1
            else:
                line_nr = pc_to_line(m, pc, METHODS) # having twice the same info is a bit ugly, didn't want to mess up ret, though.
            ret[m][pc] = [line_nr, tainted]
            #lines[m][line_nr] = [pc,tainted]
    return ret#, lines

''' creates the DFG for the input APK, from the functions indicated by search, to all entry_nodes.
    a function can e.g. be input as "Lcom/example/android/skeletonapp/SkeletonActivity;->why(Ljava/lang/String; I I)".
    since this is a string match, it could be "why(" as well...
    each line is annotated with a list of variables which are tainted AT the current line of code
'''
def dfg_backward(METHODS, MEMBERS, SINKS, dex, MARKED_forward):
    '''
    General Analysis workflow:
      BACKWARDS ANALYSIS:
          every line is marked with the local variables which could lead to a taint leak

      FORWARD ANALYSIS:
          if we reach a marking for a static or a member-var, update the tainting table
          at every decision point (= the beginning of a basic block):
              we have a list of currently marked variables
              maybe have a list which indicates which variables will be tainted at the end of the block, depending on the currently marked variables
              this list would also consider, that we can jump into functions inside a basic block

    '''
    '''@todo: object stuff:
    backwards analysis:
      remember which variables of objects are modified: 
          v* are only relevant inside a function
          member variables are potentially tainted when iget/iput is called. at this point, store the instance (as id or address, or ...)
          static variables are relevant only for the Class, but not for the instance
    forward analysis:
      at iput, store the instance id and the name of the tainted variable
      at iget, check if the variable is tainted for the given instance id
    '''
    
    class BA_WorklistEntry:
        ''' an worklist entry contains:
                function:             the name of the function, the instruction is in 
                program_counter:      the actual code location (as pc, NOT as instruction of code!)
                [callstack]:          list of the parents of the function. this list is filled, if a function is called in the current node. 
                                      Then the called function gets a "pointer" to the callee, to be able to jump back. the pointer consists of function name and pc
                skip_line:            Boolean to indicate, if this instruction was generated by jumping back from a function, or if it is generated "normally"
                                      If this is true, the entry will not investigate the line further, but just jump back to the "line above"
        '''
        def __init__(self, function, pc, callstack, skip_line):
            self.function = function
            self.pc = pc
            self.callstack = callstack
            self.skip_line = skip_line
        
        def __eq__(self, other): 
            return (self.function == other.function and\
                    self.pc == other.pc and\
                    self.callstack == other.callstack and\
                    self.skip_line == other.skip_line )
            

    
    MARKED_VARS = collections.defaultdict(lambda: collections.defaultdict(list)) # hash from function to pc to marked variables
    MARKED_MEMBERS = []
    
    TODO_INSTRUCTIONS = []
    if not SINKS:
        return {},{}
    for sink in SINKS:
        sink_function_key = sink[0]
        if MARKED_forward.get(sink_function_key): #!!SHORTCUT!! 
            TODO_INSTRUCTIONS.append(BA_WorklistEntry(sink_function_key, sink[1], [], False)) 
        
    current_calculating_nodes = [i.function for i in TODO_INSTRUCTIONS] # these nodes (=functions) are currently checked. if we would step out, we wait until the node is completely done, including its function calls
    #for the first run, we have to add all variables to the marked vars!
    NEXT_TODO = []
    for ins in TODO_INSTRUCTIONS:
        current_function = ins.function       
        pc = ins.pc
        instruction = get_instruction(current_function, pc, METHODS)
        variables = get_variables_from_invoke(instruction)

        MARKED_VARS[current_function][pc].extend(variables)
        NEXT_TODO.append(BA_WorklistEntry(current_function, pc, [], True))
    TODO_INSTRUCTIONS = NEXT_TODO
#     len_before = 0
    
    while TODO_INSTRUCTIONS:
#         print "Instructions to investitate: ", len(TODO_INSTRUCTIONS)
        cnt_fun = []
#         for i in TODO_INSTRUCTIONS:
#             if i.function not in cnt_fun:
#                 cnt_fun.append(i.function)
#         print "Functions: %d, Instructions: %d" % (len(cnt_fun), len(TODO_INSTRUCTIONS))
            
        NEXT_TODO = []
        #handle all blocks + function calls, before stepping one function up
        todo = []
        for i in TODO_INSTRUCTIONS:
            if i.function in current_calculating_nodes:
                todo.append(i)
            else:
                NEXT_TODO.append(i)
        if not todo:
            NEXT_TODO = []
            current_calculating_nodes = [TODO_INSTRUCTIONS[0].function]
            continue
        
        # investigate highest pcs first
        todo = sorted(todo, key=lambda i: i.pc, reverse=True)
            
        for ins in todo:
            current_function = ins.function
            pc = ins.pc
            instruction = get_instruction(current_function, pc, METHODS)
            
            #EXTERNAL_TUNNEL_4 - To address broadcast receivers
            # callbacks
            if config.ENABLE_EXTERNAL_PATHS and pc == 0:
                for onrcv in FIRST_LINE_ONRECEIVE:
                    if current_function == onrcv[0]:
                        #We are at the beginning of onReceive - we should continue where sendBroadcast appears
                        #signature of the method is onReceive(Context, Intent) --> Intent parameter is [1]
                        mi = get_method_info(METHODS[current_function][0].method)
                        parameter_intent = 'v%s' % mi['params'][1][0]
                        #if the intent is tainted, then taint the sendBroadcast parameter (variable[1])
                        #print("parameter_intent %s ,MARKED_VARS[FIRST_LINE_ONRECEIVE[0][0]][FIRST_LINE_ONRECEIVE[0][1] %s")%(parameter_intent, MARKED_VARS[FIRST_LINE_ONRECEIVE[0][0]][FIRST_LINE_ONRECEIVE[0][1]])
                        if parameter_intent in MARKED_VARS[onrcv[0]][onrcv[1]]:
                            for intn in INTENTS_BROADCAST_SENT:
                                current_function_jm = intn[0]
                                pc_jm = intn[1]
                                instruction_jm = get_instruction(current_function_jm, pc_jm, METHODS)
                                variables_jm = get_variables_from_invoke(instruction_jm)
                                
                                if update_vars_if_not_equal(MARKED_VARS, variables_jm[1], current_function_jm, pc_jm):
                                    NEXT_TODO.append(BA_WorklistEntry(current_function_jm, pc_jm, [], False))
            
            if not ins.skip_line:
                variables = []
                
                if instruction.get_name() not in config.NOPS and 'iput' not in instruction.get_name() and 'sput' not in instruction.get_name():
                    variables = instruction.get_output().split(', ')
                    
                    function = None
                    if 'invoke-' in instruction.get_name(): #function call
                        function = variables[-1]

                    #indirect result storing
                    if 'move-resul' in instruction.get_name():
                        if '-wide' in instruction.get_name():
                            target = [variables[0], 'v' + str(int(variables[0].replace('v', ''))+1)]
                        else:
                            target = [variables[0]]
                        prev_pc = get_prev_pc(current_function, pc, METHODS)
                        MARKED_VARS[current_function][prev_pc].extend(MARKED_VARS[current_function][pc])
                        MARKED_VARS[current_function][prev_pc] = unique(MARKED_VARS[current_function][prev_pc])
                        instruction = get_prev_instruction(current_function, pc, METHODS)
                        if 'filled-new-arr' in instruction.get_name():
                            taint_propagation = False
                            for t in target:
                                if t in MARKED_VARS[current_function][pc]:
                                    taint_propagation = True
                            if taint_propagation:
                                variables = get_variables_from_invoke(instruction)
                                update_vars_if_not_equal(MARKED_VARS, variables, current_function, pc)
                        else:
                            variables = instruction.get_output().split(', ')
                            function = variables[-1]
                            if config.ENABLE_EXTERNAL_PATHS:
                                if (variables[0] in MARKED_VARS[current_function][pc]): #EXTERNAL_TUNNEL_3 - variables[0] is the storing variable of move-resul--> we have to do something only if it is tainted
                                    #now we are working with tainted instructions!
                                    #EXTERNAL_TUNNEL_ - TO ADDRESS WRITE&READ FILE ISSUE
                                    #EXTERNAL_TUNNEL_2 - changed TODO_INSTRUCTIONS to NEXT_TODO
                                    #EXTERNAL_TUNNEL_3 - Code rewriting. TO ADDRESS WRITE&READ THROUGH FILES/DATABASES/SHAREDPREFS
                                    #EXTERNAL_TUNNEL_7 - Code rewriting to improve effectiveness (full name of class added to avoid unexpected methods)
                                    if (('java/io/InputStream;->read' in function) or
                                        ('java/io/InputStreamReader;->read' in function) or
                                        ('java/io/BufferedInputStream;->read' in function) or
                                        ('java/io/ByteArrayInputStream;->read' in function) or
                                        ('java/io/DataInputStream;->read' in function) or
                                        ('java/io/FileInputStream;->read' in function) or
                                        ('java/io/FileReader;->read' in function) or
    # EXTERNAL_TUNNEL_9 - This works but it is too generic                                    ('java/io/Reader;->read' in function) or
                                        ('java/io/BufferedReader;->read' in function) or
                                        ('java/util/zip/GZIPInputStream;->read' in function) or
                                        ('android/database/sqlite/SQLiteDatabase;->query' in function) or
                                        ('android/content/SharedPreferences;->get' in function)):
                                    #@todo - readLine serves for reading both files and sockets. Try to discover which one it is.
                                        for i in STREAMS_READ:
                                            current_function_jm = i[0]     
                                            pc_jm = i[1]                                 
                                            instruction_jm = get_instruction(current_function_jm, pc_jm, METHODS)                                            
                                            temp_jm = instruction_jm.get_output().split(', ')
                                            function_jm = temp_jm[-1]
                                            variables_jm = get_variables_from_invoke(instruction_jm)
                                            #EXTERNAL_TUNNEL_8 - To prevent connecting a read with a print() with no arguments
                                            if ('read' in function and (('write' in function_jm) or ('print' in function_jm and len(variables_jm)>1))):
                                                if update_vars_if_not_equal(MARKED_VARS, variables_jm[1], current_function_jm, pc_jm):
                                                    NEXT_TODO.append(BA_WorklistEntry(current_function_jm, pc_jm, [], False))                                        
                                            elif ('query' in function and 'SQLiteDatabase;->insert' in function_jm):
                                                if update_vars_if_not_equal(MARKED_VARS, variables_jm[1:4], current_function_jm, pc_jm):                                                
                                                    NEXT_TODO.append(BA_WorklistEntry(current_function_jm, pc_jm, [], False))                                                
                                            elif ('SharedPreferences;->get' in function and 'SharedPreferences$Editor;->put' in function_jm):      
                                                if update_vars_if_not_equal(MARKED_VARS, variables_jm[2], current_function_jm, pc_jm):                                  
                                                    NEXT_TODO.append(BA_WorklistEntry(current_function_jm, pc_jm, [], False))                                                
                                    #EXTERNAL_TUNNEL_2 - TO ADDRESS LEAKAGE THROUGH INTENTS
                                    elif 'getIntent' in function:
                                        for intn in INTENTS_WRITE:
                                            current_function_jm = intn[0]
                                            pc_jm = intn[1]
                                            instruction_jm = get_instruction(current_function_jm, pc_jm, METHODS)
                                            temp_jm = instruction_jm.get_output().split(', ')
                                            function_jm = temp_jm[-1]
                                            variables_jm = get_variables_from_invoke(instruction_jm)
                                            if ('FromChild' in function_jm or 'FromFragment' in function_jm):
                                                if update_vars_if_not_equal(MARKED_VARS, variables_jm[2], current_function_jm, pc_jm):
                                                    NEXT_TODO.append(BA_WorklistEntry(current_function_jm, pc_jm, [], False))
                                            else:
                                                if update_vars_if_not_equal(MARKED_VARS, variables_jm[1], current_function_jm, pc_jm):
                                                    NEXT_TODO.append(BA_WorklistEntry(current_function_jm, pc_jm, [], False))
                                    #EXTERNAL_TUNNEL_5 - TO ADDRESS LEAKAGE THROUGH CONTENT PROVIDERS
                                    #EXTERNAL_TUNNEL_8 - Including android/content in the condition to make it as precise as possible                          
                                    elif 'android/content/ContentResolver; query' in function:
                                        for intn in CONTENT_PROV_WRITE:
                                            current_function_jm = intn[0]
                                            pc_jm = intn[1]
                                            instruction_jm = get_instruction(current_function_jm, pc_jm, METHODS)
                                            temp_jm = instruction_jm.get_output().split(', ')
                                            function_jm = temp_jm[-1]
                                            variables_jm = get_variables_from_invoke(instruction_jm)
                                            if update_vars_if_not_equal(MARKED_VARS, variables_jm[2], current_function_jm, pc_jm):
                                                NEXT_TODO.append(BA_WorklistEntry(current_function_jm, pc_jm, [], False))                                                
                        #ENDIF config.ENABLE_EXTERNAL_PATHS
                                                    
                        #shortcut, but remember target!
                        ins = BA_WorklistEntry(current_function, prev_pc, ins.callstack, ins.skip_line)
                        pc = ins.pc
                    elif 'throw' == instruction.get_name():
                        block = get_block(METHODS, current_function, pc)
                        if block.exception_analysis:
                            for ex in block.exception_analysis.exceptions:
                                #all exceptions are interesting in backward!
                                next_pc = ex[1]
                                instruction_next =  get_instruction(current_function, next_pc, METHODS)
                                if 'move-exception' == instruction_next.get_name():
                                    variable_next = instruction_next.get_output().split(', ')[0]
                                    if variable_next in MARKED_VARS[current_function][next_pc]:
                                        if variables[0] not in MARKED_VARS[current_function][pc]:
                                            MARKED_VARS[current_function][pc].append(variables[0])
                                            MARKED_VARS[current_function][pc] = unique(MARKED_VARS[current_function][pc])
                    elif 'iget' in instruction.get_name()\
                      or 'sget' in instruction.get_name(): 
                        if '-wide' in instruction.get_name():
                            target = [variables[0], 'v' + str(int(variables[0].replace('v', ''))+1)]
                        else:
                            target = [variables[0]]
                        #currently only for instances in the current DEX!
                        if [i for i in target if i in MARKED_VARS[current_function][pc]]: # do we have taint propagation?
                            member = variables[-1]
                            MARKED_MEMBERS.append(member)
                            MARKED_MEMBERS = unique(MARKED_MEMBERS)
                            variables = variables[0:-1] #remove variable name
                            if MEMBERS.get(member) and MEMBERS[member].get('write'):
                                for ref in MEMBERS[member]['write']:
                                    calling_function = ref[0]
                                    location = ref[1]
                                    instruction_inner = pc_to_instruction(calling_function, location, METHODS)
                                    variables_inner = instruction_inner.get_output().split(', ')[0:-1] #remove field name #last entry is THIS
                                    if 'iput' in instruction_inner.get_name():
                                        variables_inner = variables_inner[:1] #remove THIS
                                    if update_vars_if_not_equal(MARKED_VARS, variables_inner, calling_function, location):
                                        NEXT_TODO.append(BA_WorklistEntry(calling_function, location, [], True))
                    elif instruction.get_name() in config.INSTRUCTION_PROPAGATION:
                        propagation = False
                        for i, v in enumerate(variables):
                            if i in config.INSTRUCTION_PROPAGATION[instruction.get_name()][0]:
                                if v in MARKED_VARS[current_function][pc]:
                                    propagation = True
                                if '-wide' in instruction.get_name() and 'v'+str(int(v.replace('v', ''))+1) in MARKED_VARS[current_function][pc]:
                                    propagation = True
                        if propagation:
                            tainted = []
                            for i, v in enumerate(variables):
                                if i in config.INSTRUCTION_PROPAGATION[instruction.get_name()][1]:
                                    tainted.append(v)
                            variables = tainted
                        else:
                            variables = []
                        MARKED_VARS[current_function][pc].extend(variables)
                        MARKED_VARS[current_function][pc] = unique(MARKED_VARS[current_function][pc])
                    elif instruction.get_name() in config.UNTAINT:
                        if '-wide' in instruction.get_name():
                            target = [variables[0], 'v' + str(int(variables[0].replace('v', ''))+1)]
                        else:
                            target = [variables[0]]
                        # for simple instructions only (e.g. add **). all other functions are handled via invoke-
                        for t in target:
                            if t in MARKED_VARS[current_function][pc]: # for simple instructions only (e.g. add **). all other functions are handled via invoke- 
                                MARKED_VARS[current_function][pc].remove(t)
                    elif instruction.get_name() in config.NOPS:
                        pass
                    else:
                        if not function:
                            print instruction.get_name(), " not configured."
                    
                    if function:
                        variables = get_variables_from_invoke(instruction)
                        #fix function name
                        ex = function.split('(')
                        ex2 = ex[0].split('->')
                        fun_name = '%s %s (%s' % (ex2[0], ex2[1], ex[1])
                        
                                                
                        propagating = check_function(fun_name, METHODS) #also does void functions. needed for static stuff
                        if propagating[0] == 0:
                            #check if var is tainted in next_line
                            _, nins = get_next_instruction_and_pc(current_function, pc, METHODS)
                            taint_propagation = False
                            if 'move-result' in nins.get_name():
                                next_variables = nins.get_output().split(', ')
                                
                                if 'wide' in nins.get_name():
                                    next_variables = [next_variables[0], 'v' + str(int(next_variables[0].replace('v', ''))+1)]
                                    
                                if [i for i in next_variables if i in MARKED_VARS[current_function][pc]]:
                                    taint_propagation = True
                            added_todo = False
                            for ret in propagating[1]:
                                investigate = True
                                if ret[1] and taint_propagation:
                                    update_vars_if_not_equal(MARKED_VARS, ret[1], fun_name, ret[0])
                                else:
                                    if '-static' not in instruction.get_name() and variables[0] in MARKED_VARS[current_function][pc]: #tainted this!
                                        taint_propagation = True
                                        mi = get_method_info(METHODS[fun_name][0].method)
                                        instance_var = 'v%d' % mi['registers'][1]
                                        if instance_var not in set(MARKED_VARS[fun_name][ret[0]]):
                                            MARKED_VARS[fun_name][ret[0]].append(instance_var)
                                            MARKED_VARS[fun_name][ret[0]] = unique(MARKED_VARS[fun_name][ret[0]])
                                        else:
                                            investigate = False
                                if investigate:
                                    if [current_function, pc] in ins.callstack: # somewhere on the stack, we have the exact copy of the next_todo already. skip this, to prevent endless loop
                                        #print "RECURSION! in", current_function
                                        pass
                                    elif not taint_propagation and MARKED_VARS[fun_name].get(ret[0]): #we were already at this location and do not need to step into. just add prev line
                                        NEXT_TODO.append(BA_WorklistEntry(current_function, pc, ins.callstack, True))
                                        added_todo = True
                                    else:
                                        NEXT_TODO.append(BA_WorklistEntry(fun_name, ret[0], ins.callstack + [[current_function, pc]], False))
                                        added_todo = True
                            if added_todo:
                                continue
                        else:
                            #error, function not found, assuming all tainted
                            #assume parameters tainted, but only if the result is also tainted
                            #                           or the instance is tainted
                            block = get_block(METHODS, current_function, pc)
                            next_pc, next_instruction = get_next_instruction_and_pc(current_function, pc, METHODS)
                            while next_pc < block.end - block.last_length and 'move-result' not in next_instruction.get_name():
                                next_pc, next_instruction = get_next_instruction_and_pc(current_function, next_pc, METHODS)
                            result_tainted = False
                            if 'move-result' not in next_instruction.get_name():
                                pass
                            else:
                                v  = next_instruction.get_output()
                                if v in MARKED_VARS[current_function][next_pc]:
                                    result_tainted = True
                                if '-wide' in next_instruction.get_name() and 'v'+str(int(v.replace('v', ''))+1) in MARKED_VARS[current_function][next_pc]:
                                    result_tainted = True
                            if '-static' not in instruction.get_name() and  variables[0] in MARKED_VARS[current_function][pc]:
                                    result_tainted = True
                            if result_tainted:
                                MARKED_VARS[current_function][pc].extend(variables)
                                MARKED_VARS[current_function][pc] = unique(MARKED_VARS[current_function][pc])
                    
            
            if pc == 0: #method start
                MARKED_VARS[current_function][-1] = unique(MARKED_VARS[current_function][0])
                #here, the function call itself is already handled, go one up!
                method = METHODS[current_function][0].method
                params = get_method_info(method).get('params')
                mi = get_method_info(METHODS[current_function][0].method)
                instance_var = 'v%d' % mi['registers'][1]
                callees = []
                callees_callees = []
                if ins.callstack: # this was a function call from an investigated basic block, just jump back and restore the callee
                    callees = [ins.callstack[-1]]
                    callees_callees = ins.callstack[:-1]
                else: #this is a "normal" function beginning. search all callees and continue at the points where they jumped into this function.
                    # This can only happen in the current dex file, since all sinks and sources will be in it, and all direkt paths will also be.
                    key2 = '%s %s %s' % (method.get_class_name(), method.get_name(), method.get_descriptor())
                    for parent in METHODS[key2][0].method.XREFfrom.items:
                        parent_key = '%s %s %s' % (parent[0].get_class_name(), parent[0].get_name(), parent[0].get_descriptor())
                        for entry in parent[1]:
                            if entry:
                                callees.append([parent_key, entry.idx])
                for entry in callees:
#                     print "\tJumping back to", entry
                    calling_function = entry[0]
                    location = entry[1]
                    instruction = pc_to_instruction(calling_function, location, METHODS)
                    variables = get_variables_from_invoke(instruction)

                    new_marked = []
                    this_var = None
                    if 'invoke-static' in instruction.get_name():
                        pass 
                    else:
                        this_var = variables[0]
                        variables = variables[1:len(variables)] #first variable is THIS
                        
                        if instance_var in MARKED_VARS[current_function][-1]:
                            #print 'THIS Instance %s is tainted, tainting instance var %s of caller %s' % (instance_var, this_var, calling_function)
                            new_marked.append(this_var)
                        elif MARKED_VARS.get(calling_function)\
                            and MARKED_VARS[calling_function].get(location)\
                            and this_var in MARKED_VARS[calling_function].get(location)\
                            and instance_var not in MARKED_VARS[current_function][-1]: #remove instance var
                                new_marked = [i for i in MARKED_VARS[calling_function][location] if i != this_var]
                                MARKED_VARS[calling_function][location] = new_marked
                                MARKED_VARS[calling_function][location] = unique(MARKED_VARS[calling_function][location])
                                var_changed = True
                    for i in range(len(params)):
                        if "v%s" % params[i][0] in MARKED_VARS[current_function][-1]:
                            new_marked.append(variables[i])
                    var_changed = False
                    if new_marked\
                        and update_vars_if_not_equal(MARKED_VARS, new_marked, calling_function, location):
                            var_changed = True
                            
                    if (var_changed and not calling_function == current_function) or ins.callstack:
                        NEXT_TODO.append(BA_WorklistEntry(calling_function, location, callees_callees, True))
               
                            
            else:
                block = get_block(METHODS, current_function, pc)
                if pc == block.start: #block start (but not first block!)
                    #search for exceptions:
                    for bb in METHODS[current_function][0].basic_blocks.bb:
                        if bb.exception_analysis:
                            for ex in bb.exception_analysis.exceptions:
                                if pc == ex[1]:
                                    prev_pc = bb.end - bb.last_length
                                    if update_vars_if_not_equal(MARKED_VARS, MARKED_VARS[current_function][pc], current_function, prev_pc):
                                            NEXT_TODO.append(BA_WorklistEntry(current_function, prev_pc, ins.callstack, False))
                                    elif ins.callstack is not None: #no tainting is changed, but we are called from a function. So we go to the first instruction of the function, and then jump back in the following round
                                        NEXT_TODO.append(BA_WorklistEntry(current_function, 0, ins.callstack, True))
                                    elif 'throw' in get_instruction(method, prev_pc, METHODS).get_name(): #if a th1row, we can have several paths, and always have to check...
                                        NEXT_TODO.append(BA_WorklistEntry(current_function, prev_pc, ins.callstack, False))
                    for pre in block.fathers: #continue at all father.ends of the block
                        father = pre[2]
                        prev_pc = father.end - father.last_length
                        if update_vars_if_not_equal(MARKED_VARS, MARKED_VARS[current_function][pc], current_function, prev_pc):
                                NEXT_TODO.append(BA_WorklistEntry(current_function, prev_pc, ins.callstack, False))
                        elif ins.callstack is not None: #no tainting is changed, but we are called from a function. So we go to the first instruction of the function, and then jump back in the following round
                            NEXT_TODO.append(BA_WorklistEntry(current_function, 0, ins.callstack, True))
                        elif 'throw' in get_instruction(method, prev_pc, METHODS).get_name(): #if a throw, we can have several paths, and always have to check...
                            NEXT_TODO.append(BA_WorklistEntry(current_function, prev_pc, ins.callstack, False))
                else: #just a "normal" instruction in a BB
                    prev_pc = get_prev_pc(current_function, pc, METHODS)
                    if update_vars_if_not_equal(MARKED_VARS, MARKED_VARS[current_function][pc], current_function, prev_pc):
                            NEXT_TODO.append(BA_WorklistEntry(current_function, prev_pc, ins.callstack, False))
                    elif ins.callstack is not None: #no tainting is changed, but we are called from a function. So we go to the first instruction of the function, and then jump back in the following round
                        NEXT_TODO.append(BA_WorklistEntry(current_function, 0, ins.callstack, True))
                    
        TODO_INSTRUCTIONS = []
        for e in NEXT_TODO:
            if MARKED_forward.get(e.function): #only add the functions we really want to investigate (=have an annotation in the forward analysis)
                if e not in TODO_INSTRUCTIONS: #more complex test, unhashable -> list(set( not available
                    TODO_INSTRUCTIONS.append(e)
                
    #return infos for smali instrumentation (class, method, instruction nr)
    ret,lines = {},{}
    for m, e in MARKED_VARS.items():
        ret[m], lines[m] = {}, {}
        for pc, tainted in e.items():
            if pc == -1:
                line_nr = -1
            else:
                line_nr = pc_to_line(m, pc, METHODS)    # having twice the same info is a bit ugly, didn't want to mess up ret, though.
            ret[m][pc] = [line_nr, tainted]
            lines[m][line_nr] = [pc,tainted]
    return ret, lines

def dfg_combine(MARKED_VARS_backward, MARKED_VARS_forward, types, METHODS, SOURCES, SINKS):
    MARKED_combined = collections.defaultdict(lambda: collections.defaultdict(list))
    MARKED_combined_reversed = collections.defaultdict(lambda: collections.defaultdict(list))
    
    for function, entry in MARKED_VARS_forward.items():
        for pc, marked_forward in entry.items():
            if marked_forward and MARKED_VARS_backward.get(function) and MARKED_VARS_backward[function].get(pc):
                for var in marked_forward[1]:
                    if var in MARKED_VARS_backward[function][pc][1]:
                        inner = MARKED_combined[function][pc]
                        if not inner:
                            inner = [MARKED_VARS_backward[function][pc][0], []]
                        inner[1].append(var)
                        MARKED_combined[function][pc] = inner
                        MARKED_combined_reversed[function][inner[0]] = [pc, inner[1]]
                        
    MARKED_forward_reversed = collections.defaultdict(lambda: collections.defaultdict(list))
    for f, e in MARKED_VARS_forward.items():
        for pc, inner in e.items():
            MARKED_forward_reversed[f][inner[0]] = [pc, inner[1]]
    # annotation: display what happens in each line
    
    annotations = collections.defaultdict(fun)
    for function, entry in MARKED_combined_reversed.items():
        entry_line =  min(entry, key=entry.get)
        if entry_line == -1:
            entry_line = 0
            if MARKED_combined_reversed.get(function) and MARKED_combined_reversed[function].get(-1):  
                current_marked = MARKED_combined_reversed[function][-1][1]
                with_type = get_variables_with_type_pc(current_marked, function, -1, METHODS, types)
                annotations[function][0]['marked_if_parameter_marked'].extend(with_type) #write this into line 0!!
        worklist = [[-1, entry_line]] # prev_line, current_line
        done_lines = []
        marked = collections.defaultdict(list)
        while worklist:
            next_work = []
            for w in worklist:
                line = w[1]
                prev_line = w[0]
                done_lines.append(line)
                pc = line_to_pc(function, line, METHODS)
                if pc is None: #this can happen since we just add line+1 and do not care before if this runs over the borders.
                    #outside function
                    continue
                if pc == 0:
                    marked[prev_line] = []
                    if MARKED_combined_reversed.get(function) and MARKED_combined_reversed[function].get(line):
                        current_marked = MARKED_combined_reversed[function][line][1]
                    else:
                        #continue
                        current_marked = []
                    if MARKED_combined_reversed.get(function) and MARKED_combined_reversed[function].get(-1):
                        marked[prev_line] = MARKED_combined_reversed[function][-1][1]
                    marked[line] = current_marked
                    
                block = get_block(METHODS, function, pc)
                next_line = []    
                if pc == block.end - block.last_length:
                    for c in block.childs:
                        nl = pc_to_line(function, c[2].start, METHODS)
                        next_work.append([line, nl])
                        next_line.append(nl)
                    if block.exception_analysis:
                        for ex in block.exception_analysis.exceptions:
                            if block.exception_analysis:
                                for ex in block.exception_analysis.exceptions:
                                    npc = pc_to_line(function, ex[1], METHODS)
                                    next_line.append(npc) #next line
                else:
                    next_line = [line + 1]
                    next_work.append([line, line + 1])
                    
                    
                if entry.get(line):
                    current_marked = entry.get(line)[1]
                    marked[line] = current_marked
                elif entry.get(prev_line):
                    current_marked = []
                    marked[line] = current_marked
                else:
                    marked[line] = marked[prev_line]
                    next_work.append([line, line + 1])
                    continue

                instruction = get_instruction(function, pc, METHODS)
#                    print "(%s) 0x%x %s %s" % (function, pc, instruction.get_name(), instruction.get_output())
                
                if 'if-' in instruction.get_name():
                    if [line, line + 1] not in next_work:
                        next_work.append([line, line + 1])
                hideMarking = False 
                if MARKED_combined_reversed.get(function) and MARKED_combined_reversed[function].get(line):
                    
                    if 'invoke' in instruction.get_name():
                        variables = get_variables_from_invoke(instruction)

                        if [i for i in SINKS if i[0] == function and i[1] == pc]:
                            if MARKED_combined_reversed[function].get(prev_line):
                                marked_before = MARKED_combined_reversed[function][prev_line][1]
                            else:
                                marked_before = []
                            params = [i for i in variables if i in marked_before]
                            if params:
                                # check if the current line is an invoke with a function we do not have as code. 
                                # if so, only the vars which were tainted in the previous line need to be treated as tainted.
                                with_type = get_variables_with_type_pc(params, function, pc, METHODS, types)
                                with_type = [i for i in with_type if i.split(':')[0] in current_marked]
                                annotations[function][pc]['SINK'].extend(with_type)
                        else:
                            params = [i for i in variables if i in current_marked]
                            if params:
                                with_type = get_variables_with_type_pc(params, function, pc, METHODS, types)
                                current_marked = MARKED_combined_reversed[function][line][1]
                                with_type = [i for i in with_type if i.split(':')[0] in current_marked]
                                if with_type:
                                    annotations[function][pc]['function'].extend(with_type)
                            #print "%s 0x%x"% (function, pc), with_type, len(with_type)
                        current_marked = []
                    elif 'move-result' in instruction.get_name():
                        ppc = line_to_pc(function, line - 1, METHODS)
                        if [i for i in SOURCES if i[0] == function and i[1] == ppc]:
                            # we are at a source, mark the return value
                            variables = [instruction.get_output()]
                            with_type = get_variables_with_type_pc(variables, function, pc, METHODS, types)
                            #annotations[function][pc]['marking'].extend(with_type)
                            annotations[function][pc]['SOURCE'].extend(with_type)
                            #pass
                        else:
                            if annotations[function][ppc].get('function'):
                                variables = [instruction.get_output()]
                                if '-wide' in instruction.get_name():
                                    v1 = (str(int(variables[0].replace('v', ''))+1))
                                    variables.append('v%s' % v1)
                                with_type = get_variables_with_type_pc(variables, function, pc, METHODS, types)
                                if [i for i in variables if i in current_marked]:
                                    annotations[function][pc]['propagate_function_return'].append(with_type[0])
                                    if '-wide' in instruction.get_name():
                                        annotations[function][pc]['propagate_function_return'].append(with_type[1])
                                else:
                                    annotations[function][pc]['unmarking'].append(with_type[0])
                                    if '-wide' in instruction.get_name():
                                        annotations[function][pc]['unmarking'].append(with_type[1])
                            current_marked = []
                        continue
                        
                    elif 'return' in instruction.get_name():
                        variables = instruction.get_output().split(', ')
                        params = [i for i in variables if i in current_marked]
                        #todo: return wide?!
                        if params:
                            with_type = get_variables_with_type_pc(params, function, pc, METHODS, types)
                            current_marked = MARKED_combined_reversed[function][line][1]
                            with_type = [i for i in with_type if i.split(':')[0] in current_marked]
                            annotations[function][pc]['return'].extend(with_type)
                        continue
                    
                    elif 'sput-' in instruction.get_name(): #storing in static
                        variables = instruction.get_output().split(', ')
                        if variables[0] in current_marked:
                            inst = variables[-1].split(' ')
                            typ = inst[1][1:-1].replace('/', '.')
                            inst = inst[0][1:].replace('/', '.').replace(';->', '.') #*wink*
                            with_type = '%s: %s' % (inst, typ)
                            annotations[function][pc]['marking_staticvar'].append(with_type)
                            hideMarking = True
#                         continue
                    elif 'iput-' in instruction.get_name(): #storing in member
                        variables = instruction.get_output().split(', ')
                        if variables[0] in current_marked:
                            inst = variables[-1].split(' ')
                            typ = inst[1][1:-1].replace('/', '.')
                            inst = inst[0][1:].replace('/', '.').replace(';->', '.') #*wink*
                            with_type = '%s: %s: %s' % (variables[1], inst, typ)
                            annotations[function][pc]['marking_instancevar'].append(with_type)
                            hideMarking = True
#                         continue
                    elif 'sget-' in instruction.get_name(): #loading static
                        variables = instruction.get_output().split(', ')
                        if variables[0] in current_marked:
                            inst = variables[-1].split(' ')
                            typ = inst[1][1:-1].replace('/', '.')
                            inst = inst[0][1:].replace('/', '.').replace(';->', '.') #*wink*
                            with_type = '%s: %s: %s' % (inst, variables[0], typ)
                            annotations[function][pc]['propagate_staticvar'].append(with_type)
                            hideMarking = True
#                         continue
                    elif 'iget-' in instruction.get_name(): #loading member
                        variables = instruction.get_output().split(', ')
                        if variables[0] in current_marked:
                            inst = variables[-1].split(' ')
                            typ = inst[1][1:-1].replace('/', '.')
                            inst = inst[0][1:].replace('/', '.').replace(';->', '.') #*wink*
                            with_type = '%s: %s: %s: %s' % (variables[1], inst, variables[0], typ)
                            annotations[function][pc]['propagate_instancevar'].append(with_type)
                            hideMarking = True
#                         continue
            
                new_marked = [i for i in current_marked if i not in marked[prev_line]]
                if next_line:
                    new_un_marked = []
                    for nl in next_line:
                        if entry.get(nl):
                            tmp = [i for i in current_marked if i not in entry[nl][1]]
                            if MARKED_combined_reversed.get(function) and MARKED_combined_reversed[function].get(line):
                                tmp = [i for i in tmp if i in MARKED_combined_reversed[function][line][1]]
                                if tmp:
                                    npc = line_to_pc(function, nl, METHODS)
                                    new_un_marked.append([npc, tmp])
                else:
                    new_un_marked = []
                
                if new_marked and not hideMarking:
                    instruction = get_instruction(function, pc, METHODS).get_output().split(', ')
                    if '->' in instruction[-1]:
                        instruction = instruction[:-1]
                    with_type = get_variables_with_type_pc(new_marked, function, pc, METHODS, types)
                    #only annotate markings, if these are set in the current line.
                    # a var could be not tainted in prev_line, but in line, if the var is only marked via a different path.
                    if pc != 0:
                        with_type = [i for i in with_type if i.split(':')[0] in instruction]
                    if MARKED_combined_reversed.get(function) and MARKED_combined_reversed[function].get(line):
                        current_marked = MARKED_combined_reversed[function][line][1]
                        with_type = [i for i in with_type if i.split(':')[0] in current_marked]
                        if with_type:
                            annotations[function][pc]['marking'].extend(with_type)
                if new_un_marked:
                    for i in new_un_marked:
                        next_pc = i[0]
                        with_type = get_variables_with_previous_type_pc(i[1], function, pc, METHODS, types)
                        annotations[function][next_pc]['unmarking'].extend(with_type)
                    
                
            worklist = []
            for j in [i for i in next_work if i[1] not in done_lines]:
                if j not in worklist:
                    worklist.append(j)
                    
    annotations_rev = collections.defaultdict(fun)
    for m, e in annotations.items():
        for pc, inner in e.items():
            line_nr = pc_to_line(m, pc, METHODS)
            annotations_rev[m][line_nr] = inner
    return MARKED_combined, annotations, annotations_rev

def type_checking(MARKED_VARS_backward, MARKED_VARS_forward, METHODS, dex):
    '''
    codes which are not generating output:
        return-void
        goto
        switch
    '''
    TYPES_line = collections.defaultdict(lambda: collections.defaultdict(list))
    TYPES_total = collections.defaultdict(lambda: collections.defaultdict(list))
    TYPES_total_cpy = collections.defaultdict(lambda: collections.defaultdict(list))
    for m in dex.methods.methods:
        current_function = '%s %s %s' % (m.get_class_name(), m.get_name(), m.get_descriptor())
        if not current_function in METHODS or (not MARKED_VARS_backward.get(current_function) and not MARKED_VARS_forward.get(current_function)):
            continue
#         print "Creating types for %s" % current_function
        
        mi = get_method_info(METHODS[current_function][0].method)
        
        if 'params' in mi:
            params = ['v%d: %s' % (i[0], i[1]) for i in mi['params']]
        else:
            params = []
        
        if METHODS[current_function][0].method.get_access_flags_string() != 'static':
            #add THIS to parameters.
            params.append('v%d: %s' % (mi['registers'][1], m.get_class_name()[1:-1].replace('/', '.')))
        todo_registers = ['v%d' % t for t in range(mi['registers'][0], mi['registers'][1]+1)]
        
        entry = check_function(current_function, METHODS)
        #add throw blocks (function could throw to parent)
        for bb in METHODS[current_function][0].basic_blocks.bb:
            if not bb.exception_analysis:
                last_instruction_pc = bb.end - bb.last_length
                last_instruction = get_instruction(current_function, last_instruction_pc, METHODS)
#                 name = last_instruction.get_name()
#                 output = last_instruction.get_output()
                if last_instruction.get_name() == 'throw':
                    if entry[0] == -1:
                        entry[0] = 0
                        entry[1] = [[last_instruction_pc, [last_instruction.get_output()]]]
                    else:
                        entry[1].append([last_instruction_pc, [last_instruction.get_output()]])
        if entry[0] == -1:
            continue
        return_type = dvm.get_type(m.get_proto()[1])
    
        done_lines = []
        worklist = [i[0] for i in entry[1]]
        while worklist:
            new_worklist = []
            for pc in worklist:
                done_lines.append(pc)
                block = get_block(METHODS, current_function, pc)
                instruction = get_instruction(current_function, pc, METHODS)
                variables = instruction.get_output().split(', ')
                name = instruction.get_name()
                
                if 'return' in name:
                    if 'void' in name:
                        pass
                    else:
                        TYPES_line[current_function][pc] = ["%s: %s" % (variables[0], return_type)]
                        TYPES_total[current_function][variables[0]].append(return_type)
                elif 'invoke' in name:
                    function = variables[-1]
                    variables = get_variables_from_invoke(instruction)

                    cl = function.split(';->')[0][1:]
                    variable_types_function = function.split('(')[1].split(')')[0].split(' ')
                    ret_type = function.split(')')[1]
                    
                    variable_types = []
                    for v in variable_types_function:
                        if v == '':
                            continue
                        t = dvm.get_type(v)
                        if t in ('long', 'double'):
                            variable_types.append('%s_high' % t)
                            variable_types.append('%s_low' % t)
                        else:
                            variable_types.append('%s' % t)
                        
                        
                    if len(variable_types) < len(variables): #static function call
                        TYPES_line[current_function][pc].append('%s: %s' % (variables[0], cl.replace('/', '.')))
                        TYPES_total[current_function][variables[0]].append(cl.replace('/', '.'))
                        variables = variables[1:]
                    for i, v in enumerate(variables):
                        TYPES_line[current_function][pc].append('%s: %s' % (v, variable_types[i]))
                        TYPES_total[current_function][variables[0]].append(variable_types[i])
                    if ret_type != 'V':
                        next_pc, next_instruction = get_next_instruction_and_pc(current_function, pc, METHODS)
                        next_variables = next_instruction.get_output().split(', ')
                        if 'move-result-wide' in next_instruction.get_name():
                            TYPES_line[current_function][next_pc].append('%s: %s_high' % (next_variables[0], dvm.get_type(ret_type)))
                            TYPES_total[current_function][next_variables[0]].append('%s_high'%dvm.get_type(ret_type))
                            v1 = 'v%s' % (str(int(next_variables[0].replace('v', ''))+1))
                            TYPES_line[current_function][next_pc].append('%s: %s_low' % (v1, dvm.get_type(ret_type)))
                            TYPES_total[current_function][v1].append('%s_low'%dvm.get_type(ret_type))
                        elif 'move' in next_instruction.get_name():
                            TYPES_line[current_function][next_pc].append('%s: %s' % (next_variables[0], dvm.get_type(ret_type)))
                            TYPES_total[current_function][next_variables[0]].append(dvm.get_type(ret_type))
                elif 'filled-new-arra' in name:
                    typ = dvm.get_type(variables[-1])
                    next_pc, next_instruction = get_next_instruction_and_pc(current_function, pc, METHODS)
                    next_variables = next_instruction.get_output().split(', ')
                    if 'move-result-wide' in next_instruction.get_name():
                        TYPES_line[current_function][next_pc].append('%s: %s_high' % (next_variables[0], dvm.get_type(typ)))
                        TYPES_total[current_function][next_variables[0]].append('%s_high'%dvm.get_type(typ))
                        v1 = 'v%s' % (str(int(next_variables[0].replace('v', ''))+1))
                        TYPES_line[current_function][next_pc].append('%s: %s_low' % (v1, dvm.get_type(typ)))
                        TYPES_total[current_function][v1].append('%s_low'%dvm.get_type(typ))
                    elif 'move' in next_instruction.get_name():
                        TYPES_line[current_function][next_pc].append('%s: %s' % (next_variables[0], dvm.get_type(typ)))
                        TYPES_total[current_function][next_variables[0]].append(dvm.get_type(typ))
                elif 'new-instance' == name:
                    function = variables[-1]
                    variables = variables[:-1]
                    TYPES_line[current_function][pc].append('%s: %s' % (variables[0], function[1:-1].replace('/', '.')))
                    TYPES_total[current_function][variables[0]].append(function[1:-1].replace('/', '.'))
                elif 'new-array' == name:
                    TYPES_line[current_function][pc].append('%s: %s' % (variables[0], dvm.get_type(variables[-1])))
                    TYPES_total[current_function][variables[0]].append(dvm.get_type(variables[-1]))
                elif 'sput' in name or 'sget' in name:
                    typ = dvm.get_type(variables[-1].split(' ')[1])
                    TYPES_line[current_function][pc].append('%s: %s' % (variables[0], typ))
                    TYPES_total[current_function][variables[0]].append(typ)
                elif 'iput' in name or 'iget' in name:
                    typ = dvm.get_type(variables[-1].split(' ')[1])
                    TYPES_line[current_function][pc].append('%s: %s' % (variables[0], typ))
                    TYPES_total[current_function][variables[0]].append(typ)
                    typ_inst = dvm.get_type(variables[-1].split(';->')[0])
                    TYPES_line[current_function][pc].append('%s: %s' % (variables[1], typ_inst))
                    TYPES_total[current_function][variables[1]].append(typ_inst)
                elif 'cmp' in name:
                    TYPES_line[current_function][pc].append('%s: int8' % (variables[0]))
                    TYPES_total[current_function][variables[0]].append('int8')
                elif 'array-length' == name:
                    TYPES_line[current_function][pc].append('%s: int' % (variables[0]))
                    TYPES_total[current_function][variables[0]].append('int')
                elif 'instance-of' == name:
                    TYPES_line[current_function][pc].append('%s: int' % (variables[0]))
                    TYPES_total[current_function][variables[0]].append('int')
                elif 'const' in name:
                    if 'wide' in name:
                        if name in ('const-wide/16', 'const-wide/32', 'const-wide/high16'):
                            typ = 'long'
                        elif name == 'const-wide':
                            typ = 'int64'
                        else:
                            typ = 'undefined'
                        TYPES_line[current_function][pc].append('%s: %s_high' % (variables[0], typ))
                        TYPES_total[current_function][variables[0]].append('%s_high'%typ)
                        v1 = 'v%s' % (str(int(variables[0].replace('v', ''))+1))
                        TYPES_line[current_function][pc].append('%s: %s_low' % (v1, typ))
                        TYPES_total[current_function][v1].append('%s_low'%typ)
                    else:
                        if '/high16' in name:
                            typ = 'int' #maybe?
                        elif '/' in name:
                            typ = 'int%s' % name.split('/')[1]
                        elif 'string' in name:
                            typ = 'java.lang.String'
                        elif name == 'const':
                            typ = 'int'
                        elif 'class' in name:
                            typ = 'class.%s' % variables[1]
                        else:
                            typ = 'undef'
                        TYPES_line[current_function][pc].append('%s: %s' % (variables[0], typ))
                        TYPES_total[current_function][variables[0]].append(typ)

                if pc == block.start:
                    #search for exceptions:
                    for bb in METHODS[current_function][0].basic_blocks.bb:
                        if bb.exception_analysis:
                            for ex in bb.exception_analysis.exceptions:
                                prev_pc = bb.end - bb.last_length
                                if pc == ex[1] and prev_pc not in done_lines:
                                    new_worklist.append(prev_pc)
                                if pc == ex[1]:
                                    if 'move-exception' == name:
                                        if ex[0] == 'any':
                                            typ = 'java.lang.Exception'
                                        else:
                                            typ = ex[0][1:-1].replace('/', '.')
                                        TYPES_line[current_function][pc].append('%s: %s' % (variables[0], typ))
                                        TYPES_total[current_function][variables[0]].append(typ)
                                     
                    for pre in block.fathers: #continue at all father.ends of the block
                        father = pre[2]
                        prev_pc = father.end - father.last_length
                        if prev_pc not in done_lines:
                            new_worklist.append(prev_pc)
                else:
                    prev_pc = get_prev_pc(current_function, pc, METHODS)
                    new_worklist.append(prev_pc)
            worklist = new_worklist
            
        #forward checking if we can find the other variables.
        for line in METHODS[current_function][1].items():
            pc = line[1][0]
            instruction = line[1][1]
            variables = instruction.get_output().split(', ')
            not_found = [i for i in variables if i != '' and  i[0] == 'v' and i not in "".join(TYPES_line[current_function][pc])]
            if not_found:
                
                source = []
                destination = []
                search = []
                special = ''
                type_change = False
                if 0x01 <= instruction.OP <= 0x09: 
                    search = [variables[1]]
                    source = [variables[1]]
                    destination = [variables[0]]
                elif 0x2d <= instruction.OP <= 0x31:
                    search = [variables[1], variables[2]]
                    special = 'fixed'
                    destination = instruction.get_name().split('-')[-1]
                elif 0x32 <= instruction.OP <= 0x3d:
                    search = [variables[0], variables[1]]
                #binop
                elif 0x7b <= instruction.OP <= 0x80 \
                    or 0xb0 <= instruction.OP <= 0xe2: 
                        search = [variables[1]]
                        source = [variables[1]]
                        #destination = [variables[0]]
                        special = 'fixed'
                        destination = instruction.get_name().split('-')[-1].split('/')[0]
                #type change!
                elif 0x81 <= instruction.OP <= 0x8f:
                    # this instruction can change the type. this is important for e.g. int-to-long v0 v0
                    type_change = True
                    search = [variables[1]]
                    source = [variables[1]]
                    #destination = [variables[0]]
                    special = 'fixed'
                    destination = instruction.get_name().split('-')[-1].split('/')[0]
                elif 0x90 <= instruction.OP <= 0xaf:
                    search = [variables[1], variables[2]]
                    source = [variables[1]] #same type?!!
                    special = 'fixed'
                    destination = instruction.get_name().split('-')[-1]
                elif instruction.get_name() == 'check-cast':
                    search = [variables[0]]
                elif 'iput' in instruction.get_name() or 'iget' in instruction.get_name():
                    search = [variables[1]]
                elif 'aput' in instruction.get_name() or 'aget' in instruction.get_name():
                    special = 'array'
                    search = [variables[1], variables[2]]
                    source = [variables[1]]
                    destination = [variables[0]]
                elif 'array-length' == instruction.get_name():
                    search = [variables[1]]
                elif 'monitor-' in instruction.get_name():
                    search = [variables[0]]
                elif '-switch' in instruction.get_name():
                    search = [variables[0]]
                elif 'fill-array-data' == instruction.get_name():
                    search = [variables[0]]
                elif 'instance-of' == instruction.get_name():
                    search = [variables[1]]
                elif 'filled-new-array' == instruction.get_name():
                    search = get_variables_from_invoke(instruction)
                elif 'throw' == instruction.get_name():
                    search = [variables[0]]
                    
                search = [i for i in search if i in not_found]
                
                worklist = [[pc, search]]
                first = True
                done_lines = []
                
                while worklist and search:
                    new_worklist = []
                    for runner_pc, searchlist in worklist:
                        done_lines.append(runner_pc)
                        for s in searchlist[:]:
                            found = [i for i in TYPES_line[current_function][runner_pc] if s == i.split(':')[0]]
                            if not found and runner_pc == 0:
                                found = [i for i in params if s == i.split(':')[0]]
                            if found and (not first or runner_pc == 0):
                                found = unique(found)
                                #print "Found %s. Adding to %d: %s" % (s, pc, "".join(found))
                                searchlist.remove(s)
                                TYPES_line[current_function][pc].extend(found)#("%s" % ",".join(found))
                                for f in found:
                                    temp = f.split(': ')
                                    TYPES_total[current_function][temp[0]].append(temp[1])

                        first = False
                        
                        block = get_block(METHODS, current_function, runner_pc)
                        if runner_pc == block.start:
                            #search for exceptions:
                            
                            for bb in METHODS[current_function][0].basic_blocks.bb:
                                if bb.exception_analysis:
                                    for ex in bb.exception_analysis.exceptions:
                                        prev_pc = bb.end - bb.last_length
                                        if runner_pc == ex[1] and prev_pc not in done_lines:
                                            new_worklist.append([prev_pc, searchlist])
                            for pre in block.fathers: #continue at all father.ends of the block
                                father = pre[2]
                                prev_pc = father.end - father.last_length
                                if prev_pc not in done_lines:
                                    new_worklist.append([prev_pc, searchlist])
                        else:
                            prev_pc = get_prev_pc(current_function, runner_pc, METHODS)
                            new_worklist.append([prev_pc, searchlist])
                    worklist = new_worklist
                
                post_indicator = ''
                if variables[0] in source:
                    # we overwrite a source. currently, assume that the destination type is the same as the source type.
                    # this must not be the case:
                    # v2 = float
                    # neg-int v2 v2
                    # not v2 would be int.
                    # BUT, maybe this is not allowed from the verifier.
                    if not type_change:
                        continue
                    else:
                        post_indicator = '_after'
                
                if special == 'fixed':
                    if '-long' in instruction.get_name() or '-double' in instruction.get_name():
                        TYPES_line[current_function][pc].append('%s%s: %s_high' % (variables[0], post_indicator, destination))
                        TYPES_total[current_function][variables[0]].append('%s_high'% destination)
                        v1 = 'v%s' % (str(int(variables[0].replace('v', ''))+1))
                        TYPES_line[current_function][pc].append('%s%s: %s_low' % (v1, post_indicator, destination))
                        TYPES_total[current_function][v1].append('%s_low' % destination)
                    else:
                        TYPES_line[current_function][pc].append('%s: %s' % (variables[0], destination))
                        TYPES_total[current_function][variables[0]].append('%s'% destination)
                else:
                    for s in source:
                        found = None
                        for i in TYPES_line[current_function][pc]:
                            if '%s_after: ' % s in i:
                                found = i
                                break
                            elif s == i.split(':')[0]:
                                found = i
                        #found = list(set([i for i in TYPES_line[current_function][pc] if s == i.split(':')[0]]))
                        if found:
                            for d in destination:
                                found = found.replace(s, d)
                                if special == 'array':
                                    found = found.replace('[]', '')
                                temp = found.split(': ')
                                if '-wide' in instruction.get_name():
                                    # remove _high, if such a type is "copied"
                                    if temp[1][-5:] == '_high':
                                        temp[1] = temp[1][:-5]
                                    if temp[1][-4:] == '_low':
                                        temp[1] = temp[1][:-4]
                                    TYPES_line[current_function][pc].append('%s%s: %s_high' % (temp[0], post_indicator, temp[1]))
                                    TYPES_total[current_function][temp[0]].append('%s_high'% temp[1])
                                    v1 = 'v%s' % (str(int(temp[0].replace('v', ''))+1))
                                    TYPES_line[current_function][pc].append('%s%s: %s_low' % (v1, post_indicator, temp[1]))
                                    TYPES_total[current_function][v1].append('%s_low' % temp[1])
                                else:
                                    TYPES_line[current_function][pc].append("%s%s" % (found, post_indicator))
                                    TYPES_total[current_function][temp[0]].append(temp[1])
                        else:
                            print current_function, '0x%x' % pc
                            print "Source %s not found during forward type checking" % s
                
    
        for v in TYPES_total[current_function]:
            if v in todo_registers:
                TYPES_total_cpy[current_function][v] = unique(TYPES_total[current_function][v])
        for l in TYPES_line[current_function]:
            TYPES_line[current_function][l] = list(set(TYPES_line[current_function][l]))
            

    return TYPES_total_cpy, TYPES_line

def get_variables_with_type_pc(params, function, pc, METHODS, types):
    if len(types) == 0:
        return params
    with_type = []
    for p in params:
        in_line = [i for i in types[function][pc] if p in i]
        if in_line:
            t = in_line[0].replace('%s: ' % p, '')
        else:
            mi = get_method_info(METHODS[function][0].method)
            param_function = ['%s' % i[1] for i in mi['params'] if i[0] == int(p[1:])]
            if param_function:
                t = param_function[0]
            elif int(p[1:]) == mi['registers'][1]:
                t = function.split(';')[0][1:].replace('/', '.')
            else:
                t = 'n/A'
        with_type.append('%s: %s' % (p, t))
    return with_type

def get_variables_with_previous_type_pc(params, function, pc, METHODS, types):
    with_type = []
    if pc == 0:
        mi = get_method_info(METHODS[function][0].method)
        for p in params:
            param_function = ['%s' % i[1] for i in mi['params'] if i[0] == int(p[1:])]
            if param_function:    
                t = param_function[0]
            else:
                t = 'n/A'
            with_type.append('%s: %s' % (p, t))
    else:
        worklist = [pc]
        done_lines = []
        while worklist and params:
            new_worklist = []
            for pc in worklist:
                done_lines.append(pc)
                
                for p in params[:]:
                    in_line = [i for i in types[function][pc] if "%s:"%p in i]
                    if in_line:
                        t = in_line[0].replace('%s: ' % p, '')
                        with_type.append('%s: %s' % (p, t))
                        params.remove(p)
                
                block = get_block(METHODS, function, pc)
                if pc == block.start:
                    #search for exceptions:
                    for bb in METHODS[function][0].basic_blocks.bb:
                        if bb.exception_analysis:
                            for ex in bb.exception_analysis.exceptions:
                                prev_pc = bb.end - bb.last_length
                                if pc == ex[1] and prev_pc not in done_lines:
                                    new_worklist.append(prev_pc)
                                     
                    for pre in block.fathers: #continue at all father.ends of the block
                        father = pre[2]
                        prev_pc = father.end - father.last_length
                        if prev_pc not in done_lines:
                            new_worklist.append(prev_pc)
                elif pc == 0:
                    for p in params:
                        with_type.append('%s: n/A' % (p, t))
                else:
                    new_worklist.append(get_prev_pc(function, pc, METHODS))
            worklist = new_worklist

    return with_type

def pc_to_line(method, pc, METHODS):
    return METHODS[method][3][pc][0]
#     for l, p in METHODS[method][1].items():
#         if p[0] == pc:
#             return l
#     return -1

def line_to_pc(method, line, METHODS):
    if METHODS[method][1].get(line):
        return METHODS[method][1].get(line)[0]
    return None

def pc_to_instruction(method, pc, METHODS):
    return METHODS[method][3][pc][1]
#     for _, p in METHODS[method][1].items():
#         if p[0] == pc:
#             return p[1]
#     return None

def get_prev_pc(method, pc, METHODS):
    line = pc_to_line(method, pc, METHODS)
    return METHODS[method][1][line-1][0] #sry

def get_next_pc(method, pc, METHODS):
    line = pc_to_line(method, pc, METHODS)
    return METHODS[method][1][line+1][0] #sry

def get_prev_instruction(method, pc, METHODS):
    line = pc_to_line(method, pc, METHODS)
    return METHODS[method][1][line-1][1]

def get_next_instruction_and_pc(method, pc, METHODS):
    line = pc_to_line(method, pc, METHODS)
    return METHODS[method][1][line+1]#returns[pc,instruction]

def get_instruction(method, pc, METHODS):
    line = pc_to_line(method, pc, METHODS)
    return METHODS[method][1][line][1]
            
def check_function(fun_name, METHODS):
    ''' returns a list containing [ret_code, out-locations]:
            ret_code:
                -1 if function is not found
                0 if function is found
            out-locations is a list of:
                pc of return-locations in the method
                variable the variable which would be returned at the code location (can be none for return-void)
    '''
    if fun_name not in METHODS:
        #print fun_name, "not found!"
        return [-1, None]
    else:
        return [0, METHODS[fun_name][2]]

def get_variables_from_invoke(instruction):
    variables = instruction.get_output().split(", ")[:-1]
    if 'range' in instruction.get_name():
        v = variables[0].replace('v', '').split(' ... ')
        if len(v) > 1:
            variables = ['v%d'%j for j in range(int(v[0]), int(v[1]) + 1)]
    return variables

def update_vars_if_not_equal(MARKED_VARS, new_vars, destination_function, destination_pc):
    if type(new_vars) != list:
        new_vars = [new_vars]
    if MARKED_VARS.get(destination_function) is None\
        or MARKED_VARS.get(destination_function).get(destination_pc) is None\
        or (set(new_vars) != set(MARKED_VARS[destination_function][destination_pc])\
            and not set(new_vars).issubset(set(MARKED_VARS[destination_function][destination_pc]))):
            MARKED_VARS[destination_function][destination_pc].extend(new_vars)
            MARKED_VARS[destination_function][destination_pc] = unique(MARKED_VARS[destination_function][destination_pc])
            return True
    else:
        return False
    
''' get parameters and register information of the function '''          
def get_method_info(method):
    info = {'registers':(0,0),'params':[]}
    if method.code is None:
        #print "WARN: Method without code skipped: %s.%s"%(method.class_name,method.name)
        return info
    nb = method.code.registers_size
    ret = method.proto.split(')')
    params = ret[0][1:].split()
    inner_offset = 0
    for p in params:
        if dvm.get_type(p) in ['long', 'double']:
            inner_offset += 1
    if params:
        info["params"] = []
        info["registers"] = (0, nb - 1 - len(params) - inner_offset)
        j = 0
        inner_counter = nb - len(params) - inner_offset
        for p in params:
            t = dvm.get_type(p)
            if t in ['long', 'double']:
                info["params"].append((inner_counter, t + '_low'))
                info["params"].append((inner_counter + 1, t + '_high'))
                j += 2
                inner_counter += 2
            else:
                info["params"].append((inner_counter, t))
                inner_counter += 1
            
    else:
        info["registers"] = (0, nb - 1)
    return info

''' get the block of function m that contains the location pc '''
def get_block(METHODS, method, pc):
    return METHODS[method][3][pc][2]
#     for block in m.basic_blocks.bb:
#         if block.start <= pc < block.end:
#             return block
#     return None

''' print basic blocks of a function '''
def print_bb_childs(bb, show_code = True, prefix=''):
    for block in bb:
        print prefix, block.name, (block.start, block.end)
        #display block part of method
        if show_code:
            m = block.method
            line = 0
            pc = 0
            for ins in m.get_code().get_bc().get_instructions():
                if block.start <= pc < block.end:
                    print "\t", line, "0x%x(%d)" % (pc,pc), ins.get_name() + " " + ins.get_output(pc)
                pc += ins.get_length()
                line += 1
        #for c in block.childs:
        #    print_bb_intern(c, prefix + '\t')

''' internal function to display the childs of a bb '''
def print_bb_intern(bb, prefix=''):
    print prefix, bb[0], bb[1], bb[2].name
    for c in bb[2].childs:
        print_bb_intern(c, prefix + '\t')
        
def unique(l):
    return list(set(l))

def output_path_json(source, target, typ,  data=None):
    if data:
        print '{source="%s", target="%s", type="%s", data="%s"}' % (source, target, typ, data)
    else:
        print '{source="%s", target="%s", type="%s"}' % (source, target, typ)

def generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, m, pc, path, combined):
    path.append(m)
    for call_pc, ann in iter(sorted(annotations[m].iteritems())):
        if ann.get('function'):
            ins = get_instruction(m, call_pc, METHODS)
            tmp = ins.get_output().split(',')[-1].split('(')[0]
            tmp = tmp.split('->')
            function_name = tmp[1]
            key = tmp[0]
            if config.ENABLE_EXTERNAL_PATHS:
                if ('println' in function_name 
                    or 'write' in function_name 
                    or 'SharedPreferences$Editor;->put' in function_name 
                    or 'SQLiteDatabase;->insert' in function_name) and not key.startswith('Landroid/support'):
                    #STREAMS_READ.append([key,pc])
                    output_path_json(m, '<<FILE>>', 'file')
                    for i in STREAMS_WRITE:
                        output_path_json('<<FILE>>', i[0], 'file')
                        if i[0] not in path:
                            generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, i[0], i[1], path, combined)
                elif (('startActivity' in function_name and 'Landroid/content/Intent' in key) and not 'makeRestartActivity' in function_name):                            
                    #INTENTS_WRITE.append([key,pc])
                    output_path_json(m, '<<INTENT>>', 'intent')
                    for i in INTENTS_READ:
                        output_path_json('<<INTENT>>', i[0], 'intent')
                        if i[0] not in path:
                            generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, i[0], i[1], path, combined)
                elif 'sendBroadcast' in function_name and 'Landroid/content/Intent' in ins.get_output(pc):                            
                    #INTENTS_BROADCAST_SENT.append([key,pc])
                    output_path_json(m, '<<BROADCAST>>', 'broadcast')
                    for i in FIRST_LINE_ONRECEIVE:
                        output_path_json('<<BROADCAST>>', i[0], 'broadcast')
                        if i[0] not in path:
                            generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, i[0], i[1], path, combined)
                elif 'insert' in function_name and 'ContentResolver' in ins.get_output(pc):
                    #CONTENT_PROV_WRITE.append([key,pc])
                    output_path_json(m, '<<CONTENTPROVIDER>>', 'contentprovider')
                    for i in CONTENT_PROV_READ:
                        output_path_json('<<CONTENTPROVIDER>>', i[0], 'contentprovider')
                        if i[0] not in path:
                            generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, i[0], i[1], path, combined)
            else:                    
                spl = ins.get_output().split(', L')
                if len(spl) == 2:
                    fun = 'L' + spl[1]
                    fun = fun.replace('->', ' ')
                    fun = fun.replace('(', ' (')
                    output_path_json(m, fun, 'call')
                    if fun not in path:
                        generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, fun, 0, path, combined)
                else:
                    print "error"
        if ann.get('SINK'):
            ins = get_instruction(m, call_pc, METHODS)
            spl = ins.get_output().split(', L')
            if len(spl) == 2:
                fun = 'L' + spl[1]
                fun = fun.replace('->', ' ')
                fun = fun.replace('(', ' (')
                output_path_json(m, fun, 'sink')
            else:
                print "error"
        if ann.get('return'):
            for parent in METHODS[m][0].method.XREFfrom.items:
                parent_key = '%s %s %s' % (parent[0].get_class_name(), parent[0].get_name(), parent[0].get_descriptor())
                #check if caller is annotated
                parent_annotated = False;
                for entry in parent[1]:
                    if combined.get(parent_key) and combined.get(parent_key).get(entry.idx):
                        parent_annotated = True
                if parent_annotated:
                    output_path_json(m, parent_key, 'return')
                    if parent_key not in path:
                        generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, parent_key, 0, path, combined)
        if ann.get('marking_staticvar'):
            for i in ann.get('marking_staticvar'): 
                var = i.split(':')
                if len(var) == 2:
                    for m2 in [j for j in annotations]:
                        for call_pc2, ann in annotations[m2].iteritems():
                            if ann.get('propagate_staticvar'):
                                for j in ann.get('propagate_staticvar'): 
                                    var2 = j.split(':')
                                    if len(var2) == 3:
                                        if var2[0] == var[0]:
                                            output_path_json(m, m2, 'static')
                                            if m2 not in path:
                                                generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, m2, call_pc2, path, combined)
                                            
                                    else:
                                        print "error"
                else:
                    print "error"
        if ann.get('marking_instancevar'):
            for i in ann.get('marking_instancevar'):
                var = i.split(':')
                if len(var) == 3:
                    for m2 in [j for j in annotations]:
                        for call_pc2, ann in annotations[m2].iteritems():
                            if ann.get('propagate_instancevar'):
                                for j in ann.get('propagate_instancevar'): 
                                    var2 = j.split(':')
                                    if len(var2) == 4:
                                        if var2[1] == var[1]:
                                            output_path_json(m, m2, 'instance')
                                            if m2 not in path:
                                                generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, m2, call_pc2, path, combined)
                                            
                                    else:
                                        print "error"
                else:
                    print "error"
    
            
def print_call_stack_helper(METHODS, SOURCES, SINKS, annotations, m, pc, path, prefix=''):
    path.append(m)
    for call_pc, ann in iter(sorted(annotations[m].iteritems())):
        if ann.get('function'):
            ins = get_instruction(m, call_pc, METHODS)
            spl = ins.get_output().split(', L')
            if len(spl) == 2:
                fun = 'L' + spl[1]
                fun = fun.replace('->', ' ')
                fun = fun.replace('(', ' (')
                if fun in path:
                    #print '%s0x%x\tcall %s (loop)' % (prefix, call_pc, fun)
                    print '%s\tcall %s (loop)' % (prefix, fun)
                else:
                    if fun in [i[0] for i in SINKS]:
                        print '%s0x%x\t(SINK) call %s' % (prefix, call_pc, fun)
                        #print '%s\t(SINK) call %s' % (prefix, fun)
                    else:
                        #print '%s0x%x\tcall %s' % (prefix, call_pc, fun)
                        print '%s\tcall %s' % (prefix, fun)
                    print_call_stack_helper(METHODS, SOURCES, SINKS, annotations, fun, 0, path, '\t' + prefix)
            else:
                print prefix, ins.get_name(), ins.get_output()
        if ann.get('return'):
            for parent in METHODS[m][0].method.XREFfrom.items:
                parent_key = '%s %s %s' % (parent[0].get_class_name(), parent[0].get_name(), parent[0].get_descriptor())
                if parent_key in path:
                    #print '%s0x%x\treturn %s (loop)' % (prefix, call_pc, parent_key)
                    print '%s\treturn %s (loop)' % (prefix, parent_key)
                else:
                    #print '%s0x%x\treturn %s' % (prefix, call_pc, parent_key)
                    print '%s\treturn %s' % (prefix, parent_key)
                    print_call_stack_helper(METHODS, SOURCES, SINKS, annotations, parent_key, 0, path, '\t' + prefix)
        if ann.get('marking_staticvar'):
            for i in ann.get('marking_staticvar'): 
                var = i.split(':')
                if len(var) == 2:
                    #print '%s0x%x\tstatic_var write %s' % (prefix, call_pc, var[0])
                    print '%s\tstatic_var write %s' % (prefix, var[0])
                    for m2 in [j for j in annotations]:
                        for call_pc2, ann in annotations[m2].iteritems():
                            if ann.get('propagate_staticvar'):
                                for j in ann.get('propagate_staticvar'): 
                                    var2 = j.split(':')
                                    if len(var2) == 3:
                                        if var2[0] == var[0]:
                                            if m2 in [j[0] for j in SINKS]:
                                                #print '\t%s0x%x\t(SINK) static_var read %s' % (prefix, call_pc2, m2)
                                                print '\t%s\t(SINK) static_var read %s' % (prefix, m2)
                                            else:
                                                #print '\t%s0x%x\tstatic_var read %s' % (prefix, call_pc2, m2)
                                                print '\t%s\tstatic_var read %s' % (prefix, m2)
                                            if m2 in path:
                                                #print "\t\t%s0x%x\t%s (loop)" % (prefix, call_pc2, m2)
                                                print "\t\t%s\t%s (loop)" % (prefix, m2)
                                            else:
                                                print_call_stack_helper(METHODS, SOURCES, SINKS, annotations, m2, call_pc2, path, '\t\t' + prefix)
                                            
                                    else:
                                        print ann.get('propagate_staticvar')
                else:
                    print "ERROR", ann.get('marking_staticvar')
        if ann.get('marking_instancevar'):
            for i in ann.get('marking_instancevar'):
                var = i.split(':')
                if len(var) == 3:
                    #print '%s0x%x\tinstance_var write %s' % (prefix, call_pc, var[1])
                    print '%s\tinstance_var write %s' % (prefix, var[1])
                    for m2 in [j for j in annotations]:
                        for call_pc2, ann in annotations[m2].iteritems():
                            if ann.get('propagate_instancevar'):
                                for j in ann.get('propagate_instancevar'): 
                                    var2 = j.split(':')
                                    if len(var2) == 4:
                                        if var2[1] == var[1]:
                                            if m2 in [j[0] for j in SINKS]:
                                                #print '\t%s0x%x\t(SINK) instance_var read %s' % (prefix, call_pc2, m2)
                                                print '\t%s\t(SINK) instance_var read %s' % (prefix, m2)
                                            else:
                                                #print '\t%s0x%x\tinstance_var read %s' % (prefix, call_pc2, m2)
                                                print '\t%s\tinstance_var read %s' % (prefix, m2)
                                            if m2 in path:
                                                #print "\t\t%s0x%x\t%s (loop)" % (prefix, call_pc2, m2)
                                                print "\t\t%s\t%s (loop)" % (prefix, m2)
                                            else:
                                                print_call_stack_helper(METHODS, SOURCES, SINKS, annotations, m2, call_pc2, path, '\t\t' + prefix)
                                            
                                    else:
                                        print ann.get('propagate_staticvar')
                else:
                    print "ERROR", ann.get('marking_instancevar')
            
def generate_call_stack_json(METHODS, SOURCES, SINKS, annotations, combined):
    
    class WritableObject:
        def __init__(self):
            self.content = []
        def write(self, string):
            if string != '\n':
                self.content.append(string)
                
    class Content:
        sources = []
        sinks = []
        nodes = []
        links = []
        
        def add_node(self, s):
            if s not in self.nodes:
                self.nodes.append(s)
        def add_source(self, s):
            if s not in self.sources:
                self.sources.append(s)
        def add_sink(self, s):
            if s not in self.sinks:
                self.sinks.append(s)
        def add_link(self, s):
            if s not in self.links:
                self.links.append(s)
    
    def simplyfy_functionname(s):
        tmp = s
        #tmp = s.split(';')
        #tmp = tmp[0].split('/')[-1]
        #tmp = tmp.split('$')[0]
        return tmp
    
    def simplyfy_source_sink(s):
      if not ';->' in s:
        return s
      s = s.replace(';->', '; ')
      spl = s.split('; ')
      cl = spl[0].split('/')[-1]
      method = spl[1].split('(')[0] + "(...)"
      sig = cl + "." + method
      return sig.replace(' ', '')
                
    c = Content()
                
    out = WritableObject()
    remember = sys.stdout
    sys.stdout = out
     
    for i in SOURCES:
        if annotations.get(i[0]):
            s = METHODS[i[0]][3][i[1]][1].get_output().split('L')[1]
            c.add_source(simplyfy_source_sink(s))
            c.add_node(simplyfy_source_sink(s))
            c.add_link([simplyfy_source_sink(s), simplyfy_functionname(i[0]), 'call'])
            generate_call_stack_json_helper(METHODS, SOURCES, SINKS, annotations, i[0], i[1], [], combined)
             
    sys.stdout = remember
    

    reg = re.compile(r'{source="(.*)", target="(.*)", type="(.*?)".*')
    for line in out.content:
        m = re.search(reg, line)
        if m:
            source = simplyfy_functionname(m.group(1))
            target = m.group(2)
            c.add_node(source)
            if m.group(3) == 'sink':
                c.add_sink(simplyfy_source_sink(target))
                c.add_node(simplyfy_source_sink(target))
                c.add_link([source, simplyfy_source_sink(target), 'call']) #, m.group(3) would contain the data
            else:
                target = simplyfy_functionname(m.group(2))
                c.add_node(source)
                c.add_node(target)
                c.add_link([source, target, m.group(3)]) #, m.group(3) would contain the data
        else:
            print "error, cannot parse line: ", line
    
    #optimize graph to remove all nodes without any link out (e.g. function calls which just return a value)
    list_changed = True
    while list_changed:
        list_changed = False
        for i, n in enumerate(c.nodes[:]):
            if n == '' or n in c.sinks or n in c.sources:
                continue
            found = False
            relevant_links = []
            for l in c.links:
                if l[0] == n or l[1] == n:
                    relevant_links.append(l)
                    
            participating_nodes = []
            for l in relevant_links:
                participating_nodes.append(l[0])
                participating_nodes.append(l[1])
                if l[0] == n:
                    found = True

            participating_nodes = list(set(participating_nodes))
            
            if not found or len(participating_nodes) <= 2:
                list_changed = True
                c.nodes.remove(n)
                for l in c.links[:]:
                    if l[0] == n or l[1] == n:
                        c.links.remove(l)
          
    for l in c.links[:]:
        if l[1] not in c.nodes:
            c.links.remove(l)
            continue
        if l[0] == l[1]:
            c.links.remove(l)
    
    ret = []        
    ret.append("{")
    ret.append( '    "nodes":[')
    entry = []
    for n in c.nodes:
        group = 0
        if n in c.sources:
            group = 1
        if n in c.sinks:
            group = 2
        entry.append('        {"name":"%s", "group":"%d"}' % (n, group))
    ret.append( ',\n'.join(entry))
    ret.append( '    ],')
    ret.append( '    "links":[')
    entry = []
    for l in c.links:
        entry.append('        {"source":%d, "target":%s, "type":"%s"}' % (c.nodes.index(l[0]), c.nodes.index(l[1]), l[2]))
    ret.append( ',\n'.join(entry))
    ret.append( '    ]')
    ret.append( '}')
    
    if c.nodes or c.links:
        return "\n".join(ret)
    else:
        return None;
    
def print_call_stack(METHODS, SOURCES, SINKS, annotations):
    for i in SOURCES:
        if annotations.get(i[0]):
            print "SRC: %s 0x%x"% (i[0], i[1])
            print_call_stack_helper(METHODS, SOURCES, SINKS, annotations, i[0], i[1], [], '\t')

# needed for sys.out redirection
class NullDevice():
    def write(self, s):
        pass

def main():
    #global MARKED_VARS_backward, MARKED_VARS_forward, MARKED_combined, annotations, VARIABLE_TYPES_pc, VARIABLE_TYPES_total, apk_name, STREAMS_WRITE, STREAMS_READ
    watch = Stopwatch()
    
    beg = time.time()
    
    if len(sys.argv) > 1:
        apk_name = sys.argv[1]
    else:
        apk_name = 'SkeletonApp.apk'
    print "Analysing %s:" % apk_name
    
    #comment in to disable printing
    orig = sys.stdout
    #sys.stdout = NullDevice()

    with watch:
        METHODS, MEMBERS, SOURCES, SINKS, dex = parse_methods(apk_name, 
                                                    config.SOURCE_DEFINITION, 
                                                    config.SINK_DEFINITION)
    print "Sources: %d, Sinks: %d" % (len(SOURCES), len(SINKS))

    print "\tParsing methods took %fs" % watch.get_duration()

    if len(SOURCES) == 0 or len(SINKS) == 0:
        sys.stdout = orig
        print "Complete Analysis took %fs" % (time.time() - beg)
        print "%d sources, %d sinks" % (len(SOURCES), len(SINKS))
        return
    
    with watch:
        MARKED_VARS_forward = dfg_forward(METHODS, MEMBERS, SOURCES, dex)
        pass
    print "\tForward analysis took %fs" % watch.get_duration()
    
    with watch:
        MARKED_VARS_backward, _ = dfg_backward(METHODS, MEMBERS, SINKS, dex, MARKED_VARS_forward)
    print "\tBackward analysis took %fs" % watch.get_duration()
    
    with watch:
        VARIABLE_TYPES_total, VARIABLE_TYPES_pc = type_checking(MARKED_VARS_backward, MARKED_VARS_forward, METHODS, dex)
    print "\tType checking took %fs" % watch.get_duration()

    with watch:
        MARKED_combined, annotations, annotations_line = dfg_combine(MARKED_VARS_backward, MARKED_VARS_forward, VARIABLE_TYPES_pc, METHODS, SOURCES, SINKS)
    print "\tCombining forward and backward analysis took %fs" % watch.get_duration()

    sys.stdout = orig
    print "Complete Analysis took %fs\n" % (time.time() - beg)

    if False: # disable annotation output generation here
        import pickle
        annotations_line.__reduce__();
        with open('/tmp/annotations.pickle', 'wb') as f:
            pickle.dump(annotations_line, f)
        
        #check annotations, if a variable is not set
#        count = 0
#        for function, entry in annotations.items():
#            for pc, inner in entry.items():
#                for typ, var in inner.items():
#                    count += 1
#                    if 'n/A' in ", ".join(var):
#                        print "Variable undefined:\n\t%s" % function
#                        print "\t0x%x %s: %s" % (pc, typ, ", ".join(var)) 
    
    if True: #disable image creation here
        overflow_counter = 0
        
        with watch:
            dx = uVMAnalysis(dex)
            all_methods = [i for i in dx.get_methods()]
            print "Generating %d images." % len(all_methods)
            for m in all_methods:
                key = '%s %s %s' % (m.method.get_class_name(), m.method.get_name(), m.method.get_descriptor())
                if len(key) > 180:
                    key = key[:180] + str(overflow_counter)
                    overflow_counter += 1
                if MARKED_VARS_forward.get(key) or MARKED_VARS_backward.get(key):
                    #this is to fix the diretory methods is exists or not
                    if not os.path.exists(r'methods'):
                        #if not,we create it
                        os.mkdir(r'methods')
                    elif not os.path.isdir(r'methods'):
                        #the file is exist but is not a diretory
                        os.remove(r'methods')
                        os.mkdir(r'methods')
                    #------------------
                    #to replace <> to _.
                    filename = 'methods/ann_'+key.replace('/', '.').replace('<','_').replace('>','_')+'.png'
                    print "Creating Image for %s" % key
                    #this is my fix:                  
                    #try:
                    #    os.remove(filename)
                    #except:
                    #    pass
                    try:
                        buff = bytecode.method2dot(m , MARKED_VARS_backward.get(key), MARKED_VARS_forward.get(key), MARKED_combined.get(key), annotations.get(key), VARIABLE_TYPES_pc.get(key), VARIABLE_TYPES_total.get(key))
                        bytecode.method2format(filename, "png", m, buff )
                    except Exception as e:
                        print key
                        print e
        print "Creating method images took %fs" % watch.get_duration()
    
    print "%d sources, %d sinks" % (len(SOURCES), len(SINKS))
    
    print "Sources in:"
    cnt = 0
    sourceFound = False
    for i in SOURCES:
        if annotations.get(i[0]):# and annotations.get(i[0]).get(i[1]): 
#            print "\t%s 0x%x"% (i[0], i[1])
            cnt += 1
            sourceFound = True
    print "  found %d functions containing sources." % cnt
    print "Sinks in:"
    cnt = 0
    sinkFound = False
    for i in SINKS:
        if annotations.get(i[0]) and annotations.get(i[0]).get(i[1]):
#            print "\t%s 0x%x"% (i[0], i[1])
            cnt += 1
            sinkFound = True
    print "  found %d functions containing sinks." % cnt
    
    print "%d functions contain annotations.\n" % len(annotations)
    
    if sourceFound and sinkFound:
        print "potential data leakage: YES"
    else:
        print "potential data leakage: NO"
    
    if True:
        print ""
        js = generate_call_stack_json(METHODS, SOURCES, SINKS, annotations, MARKED_combined)
        if js:
            json_name = 'd3-visualization/data/%s.json'%apk_name.split('/')[-1].split(':')[0]
            with open(json_name, 'w+') as f:
                f.write(js)
                print "JSON written to", json_name

    if False:    
        print "\n\n\n"
        print_call_stack(METHODS, SOURCES, SINKS, annotations)
    
    #create CFG:
    #./androgexf.py -i YOURAPP.apk -o YOURAPP.gexf

if __name__ == "__main__" :
    main()
