# -*- coding: utf-8 -*-

PLUGIN_VERSION = '0.1.50'

# If True the starting address will be current function when making a sig for functions.
# SigMaker-x64 behavior is to look for 5 or more references before adding function start
FUNC_START_EA = True

# Can be set via Gui, this is just for a fallback default
PLUGIN_HOTKEY = 'Ctrl-Alt-S'


"""
    pySigMaker:

    Ported by: zoomgod - unknowncheats.me

    IDAPython port for most of the origional compiled SigMaker-x64 IDA
    plugin with some minor changes, bug-fix and new GUI.

    Credits to the origional author/contributors of SigMaker-x64
    https://github.com/ajkhoury/SigMaker-x64

    See readme for IDA/Python requirements
"""

import sys, pickle, os, shutil

PLUGIN_DIR, PLUGIN_FILENAME = sys.argv[0].rsplit('/', 1)
HOTKEY_CONFLICT = False
SIGMAKER_X64_PLUGINS = []

if PLUGIN_DIR.find('plugins') == -1:
    PLUGIN_DIR = ''
else:
    if os.path.exists('%s/sigmaker.dll' % PLUGIN_DIR):
        SIGMAKER_X64_PLUGINS.append('sigmaker.dll')

    if os.path.exists('%s/sigmaker64.dll' % PLUGIN_DIR):
        SIGMAKER_X64_PLUGINS.append('sigmaker64.dll')

    HOTKEY_CONFLICT = len(SIGMAKER_X64_PLUGINS) > 0

try:
    import tkinter
    from enum import unique, IntEnum
except:
    print('Python 3.4 > required.')
    sys.exit(0)

# Gui
from PyQt5 import Qt, QtCore, QtGui, QtWidgets

import idc
import idaapi, ida_kernwin
from idaapi import BADADDR

# Ignore this, just for when I debug gui layout issues
GUI_DBG_ENABLED = False
try:
    from SigMakerDebug import QTDebugHelper
    GUI_DBG_ENABLED = True
except:
    pass

@unique
class QueryTypes(IntEnum):
    QUERY_FIRST     = 0     # Return 1st match
    QUERY_COUNT     = 1     # Return count
    QUERY_UNIQUE    = 2     # Return True/False

@unique
class PatternType(IntEnum):
    PT_INVALID      = -1
    PT_DIRECT       = 0
    PT_FUNCTION     = 1
    PT_REFERENCE    = 2

@unique
class SigType(IntEnum):
    SIG_IDA         = 0
    SIG_CODE        = 1
    SIG_OLLY        = 2

@unique
class SigSelect(IntEnum):
    OPT_LENGTH      = 0
    OPT_OPCODES     = 1
    OPT_WILDCARDS   = 2

@unique
class LogOptions(IntEnum):
    LOG_ERROR       = 0
    LOG_RESULT      = 1
    LOG_DEBUG       = 2


#
#
#  Utility functions
#
#

class QueryStruct:
    def __init__(self, pattern=b'', mask = b'', startea=BADADDR, endea=BADADDR):
        self.pattern = pattern
        self.mask = mask
        self.startea = startea
        self.endea = endea
        self.ea = BADADDR

        if self.startea == BADADDR:
            self.startea = idaapi.inf_get_min_ea()

        if self.endea == BADADDR:
            self.endea = idaapi.inf_get_max_ea()

def BinSearch(query) -> QueryStruct:
    """
    Searches for matching sequence of bytes based on a pattern and mask

    args:
        QueryStruct

    returns:
        QueryStruct with ea filled in
    """

    startea = query.startea
    if query.startea == BADADDR:
        query.startea = idaapi.inf_get_min_ea()

    endea = query.endea
    if query.startea == BADADDR:
        query.startea = idaapi.inf_get_max_ea()

    query.ea = idaapi.bin_search( query.startea, query.endea, query.pattern, query.mask,
        idaapi.BIN_SEARCH_FORWARD,
        idaapi.BIN_SEARCH_NOBREAK | idaapi.BIN_SEARCH_NOSHOW )

    return query

def MakeBin(ida_pattern, startea=BADADDR, endea=BADADDR) -> QueryStruct:
    """
        makeBin(ida_pattern)
        Returns QueryStruct with bin_search compatible pattern and mask from an IDA style pattern
    """

    patt = bytearray()
    mask = bytearray()

    for i in ida_pattern.split(' '):
        if i == '?':
            patt.append(0)
            mask.append(0)
        else:
            patt.append(int(i, 16))
            mask.append(1)

    return QueryStruct(bytes(patt), bytes(mask), startea, endea)

def BinQuery(sig, flag = QueryTypes.QUERY_FIRST, startea=None, endea = None):
    """
    Args:
        sig : IDA style pattern string
        flag: One of QueryTypes enum members

    Return types:
        flag == QUERY_FIRST  returns ea, search stops when matches == 1
        flag == QUERY_COUNT  returns int, full search
        flag == QUERY_UNIQUE returns boolean, search stops when matches > 1
    """

    query = MakeBin(sig)

    Result = []

    query = BinSearch(query)
    while query.ea != BADADDR:

        Result.append(query.ea)

        if flag == QueryTypes.QUERY_UNIQUE and len(Result) > 1:
            break

        if flag == QueryTypes.QUERY_FIRST:
            return Result[0]

        query.startea = query.ea + 1
        ea = BinSearch(query)

    if flag == QueryTypes.QUERY_UNIQUE:
        return len(Result) == 1
    elif flag == QueryTypes.QUERY_COUNT:
        return len(Result)
    elif flag == QueryTypes.QUERY_FIRST:
        return BADADDR

    raise ValueError('Invalid flag passed')

#
#
#  Pattern converters
#
#
def Ida2Code(sig) -> str:
    """
    Ida2Code(sig)

    Convert an IDA sig to code pattern and mask

    Arg:
        sig: IDA style sig

    Returns:
        string, string
    """

    mask = ''
    patt = ''

    for entry in sig.split(' '):
        if entry == '?':
            patt = patt + '\\x00'
            mask = mask + '?'
        else:
            patt = patt + '\\x%s' % entry
            mask = mask + 'x'

    return patt, mask

def Ida2Olly(sig) -> str:
    """
    Ida2Olly(sig)

    Convert an IDA sig to an Olly Debugger compatible sig

    Arg:
        sig: IDA style sig

    Return:
        string
    """

    pattern = []

    for entry in sig.split(' '):
        if entry == '?':
            pattern.append('??')
        else:
            pattern.append(entry)

    return " ".join(pattern)

def Code2Ida(patt, mask=None) -> str:
    """
    Code2Ida(sig)

    Convert an code style sig to an IDA sig

    Note:  When no mask is supplied any \x00 in pattern become a wildcards.

    Arg:
        sig : required, code style sig
        mask: optional

    Return:
        string
    """

    pattern = []
    p = []

    # convert binary string or regular string into a list of ints
    # Since \ is an escape character in Python have to check
    # for varying strings
    if not type(patt) is type(b''):
        if type(patt) is type('') and patt.find('\\') > -1:
            p = [ int('0x%s' % x, 16) for x in patt.split('\\x')[1:] ]
        else:
            return ''
    else:
        # binary string, can just convert to list
        p = list(patt)

    if mask and len(mask) != len(p):
        return ''

    for i in range(len(p)):
        if mask:
            if mask[i] == 'x':
                pattern.append('%02X' % p[i])
            else:
                pattern.append('?')
        elif p[i] > 0:
            pattern.append('%02X' % p[i])
        else:
            pattern.append('?')

    return ' '.join(pattern)

def GetIdaSig(sig, mask = None) -> str:
    """
    GetIdaSig(sig)

    Converts Olly or Code style sigs to an IDA style sigs

    Arg:
        sig : required, olly or code style sig
        mask: optional, valid only for code sigs

    Return:
        string
    """

    # Only a code sig should be byte string
    if type(sig) is type(b''):
        return Code2Ida(sig, mask)

    if sig.find(' ') > -1:

        # an olly sig without wildcards would be same as an ida sig so this is safe
        if sig.find(' ?? ') > -1:
            return sig.replace('??', '?')

        # Olly sig with no wildcards or already an ida sig
        return sig

    # Only supported type left is code sigs as a string
    return Code2Ida(sig, mask)

def GetSigType(sig) -> SigType:

    if type(sig) is type(b'') or sig.find('\\') > -1:
        return SigType.SIG_CODE

    if sig.find(' ') > -1:
        if sig.find(' ?? ') > -1:
            return SigType.SIG_OLLY
        return SigType.SIG_IDA

    return SigType.SIG_CODE

#
#
#  SigMaker
#
#
class SigCreateStruct:
    def __init__(self):
        self.sig = []
        self.dwOrigStartAddress = BADADDR   #ea at cursor when started
        self.dwStartAddress = BADADDR
        self.dwCurrentAddress = BADADDR
        self.bUnique = False
        self.iOpCount = 0
        self.eType = PatternType.PT_INVALID

class SigMaker:
    """
    Public methods:
        AutoFunction()
        AutoAddress()
    """

    def __init__(self, plugin):
        self.__plugin = plugin
        self.Sigs = []

    def _reset(self):
        self.Sigs = []

    def _addBytesToSig(self, sigIndex, ea, size):

        for i in range(0, size):
            b = idaapi.get_byte( ea + i )
            self.Sigs[sigIndex].sig.append('%02X' % b)

    def _addWildcards(self, sigIndex, count):
        for i in range(0, count):
            self.Sigs[sigIndex].sig.append('?')

    def _getCurrentOpcodeSize(self, cmd) -> (int, int):

        count = 0

        for i in range(0, idaapi.UA_MAXOP):

            count = i
            if cmd.ops[i].type == idaapi.o_void:
                return 0, count

            if cmd.ops[i].offb != 0:
                return cmd.ops[i].offb, count

        return 0, count

    def _matchOperands(self, ea) -> bool:

        if idaapi.get_first_dref_from(ea) != BADADDR:
            return False
        elif not self.__plugin.Settings.bOnlyReliable:
            if idaapi.get_first_fcref_from(ea) != BADADDR:
                return False
        elif idaapi.get_first_cref_from(ea) != BADADDR:
            return False

        return True

    def _addInsToSig(self, cmd, sigIndex):

        size, count = self._getCurrentOpcodeSize(cmd)

        if size == 0:
            self._addBytesToSig(sigIndex, cmd.ea, cmd.size)
            return
        else:
            self._addBytesToSig(sigIndex, cmd.ea, size)

        if self._matchOperands(cmd.ea):
            self._addBytesToSig(sigIndex, cmd.ea + size, cmd.size - size)
        else:
            self._addWildcards(sigIndex, cmd.size - size)

    def _addToSig(self, sigIndex) -> bool:

        cmd = idaapi.insn_t()
        cmd.size = 0

        sig = self.Sigs[sigIndex]

        if not idaapi.can_decode(sig.dwCurrentAddress):
            return False

        count = idaapi.decode_insn(cmd, sig.dwCurrentAddress)

        if count == 0 or cmd.size == 0:
            return False

        if cmd.size < 5:
            self._addBytesToSig(sigIndex, sig.dwCurrentAddress, cmd.size)
        else:
            self._addInsToSig(cmd, sigIndex)

        sig.dwCurrentAddress = sig.dwCurrentAddress + cmd.size
        sig.iOpCount = sig.iOpCount + 1

        self.Sigs[sigIndex] = sig

        return True

    def _haveUniqueSig(self) -> bool:
        for i in range(0, len(self.Sigs)):
            if self.Sigs[i].bUnique:
                return True
        return False

    def _addRefs(self, startea) -> bool:

        self.__plugin.log('Adding references', LogOptions.LOG_DEBUG)

        if idaapi.get_func_num(startea) != -1:
            sig = SigCreateStruct()
            sig.dwStartAddress = startea
            sig.dwCurrentAddress = startea
            sig.eType = PatternType.PT_DIRECT
            self.Sigs.append(sig)
            self.__plugin.log('Added direct reference 0x%X' % startea, LogOptions.LOG_DEBUG)

        eaCurrent = idaapi.get_first_cref_to(startea)
        while eaCurrent != BADADDR:

            if eaCurrent != startea:
                sig = SigCreateStruct()
                sig.dwStartAddress = eaCurrent
                sig.dwCurrentAddress = eaCurrent
                sig.eType = PatternType.PT_REFERENCE
                self.Sigs.append(sig)
                self.__plugin.log('Added reference 0x%X' % eaCurrent, LogOptions.LOG_DEBUG)

            if self.__plugin.Settings.maxRefs > 0 and len(self.Sigs) >= self.__plugin.Settings.maxRefs:
                break

            eaCurrent = idaapi.get_next_cref_to(startea, eaCurrent)

        if len(self.Sigs) < 5:

            self.__plugin.log('Not enough references were found (%i so far), trying the function.' % len(self.Sigs), LogOptions.LOG_DEBUG)

            func = idaapi.get_func(startea)

            if not func or func.start_ea == BADADDR:
                self.__plugin.log('Selected address not in a valid function.', LogOptions.LOG_ERROR)
                return False

            if func.start_ea != startea:

                eaCurrent = idaapi.get_first_cref_to(func.start_ea)

                while eaCurrent != BADADDR:

                    if eaCurrent != startea:
                        sig = SigCreateStruct()
                        sig.dwStartAddress = func.start_ea
                        sig.dwCurrentAddress = eaCurrent
                        sig.eType = PatternType.PT_FUNCTION
                        self.Sigs.append(sig)
                        self.__plugin.log('Added function 0x%X' % eaCurrent, LogOptions.LOG_DEBUG)

                    if self.__plugin.Settings.maxRefs > 0 and len(self.Sigs) >= self.__plugin.Settings.maxRefs:
                        break

                    eaCurrent = idaapi.get_next_cref_to(func.start_ea, eaCurrent)

        if not len(self.Sigs):
            self.__plugin.log('Automated signature generation failed, no references found.', LogOptions.LOG_ERROR)
            return False

        self.__plugin.log('Added %i references.' % len(self.Sigs), LogOptions.LOG_DEBUG)

        return True

    def _chooseSig(self) -> bool:

        max = 9999
        selected = -1

        for sigIndex in range(0, len(self.Sigs)):

            sig = self.Sigs[sigIndex]

            # drop wildcards off end of sig
            while sig.sig[-1] == '?':
                sig.sig = sig.sig[:-1]

            if sig.bUnique:

                sigLen = len(sig.sig)

                if self.__plugin.Settings.SigSelect == SigSelect.OPT_LENGTH:
                    if sigLen < max or (sig.eType == PatternType.PT_DIRECT and max == sigLen):
                        max = sigLen
                        selected = sigIndex
                else:
                    if self.__plugin.Settings.SigSelect == SigSelect.OPT_OPCODES:
                        if sig.iOpCount < max or (sig.eType == PatternType.PT_DIRECT and max == sig.iOpCount):
                            max = sig.iOpCount
                            selected = sigIndex
                    else:
                        wildcards = ''.join(sig.sig).count('?')
                        if wildcards < max or sig.eType == PatternType.PT_DIRECT and max == wildcards:
                            selected = sigIndex
                            max = wildcards

        if selected == -1:
            self.__plugin.log('Failed to create signature.', LogOptions.LOG_ERROR)
            return False

        sig = self.Sigs[selected]
        idaSig = ' '.join(sig.sig)
        strSig = ''

        if self.__plugin.Settings.SigType == SigType.SIG_CODE:
            patt, mask = Ida2Code(idaSig)
            strSig = patt + ' ' + mask
        elif self.__plugin.Settings.SigType == SigType.SIG_OLLY:
            strSig = Ida2Olly(idaSig)
        else:
            strSig = idaSig

        #
        # Testing sigs for now, may just leave it, it's quick
        #
        ea = BinQuery(idaSig, QueryTypes.QUERY_FIRST)

        txt = ''

        if sig.eType == PatternType.PT_DIRECT:
            txt = 'result: matches @ 0x%X, sig direct: %s' % (ea, strSig)
        elif sig.eType == PatternType.PT_FUNCTION:
            txt = 'result: matches @ 0x%X, sig function: (+0x%X) %s' % (ea, startea - sig.dwStartAddress, strSig)
        elif sig.eType == PatternType.PT_REFERENCE:
            txt = 'result: matches @ 0x%X, sig reference: %s' % (ea, strSig)

        self.__plugin.log(txt, LogOptions.LOG_RESULT)

        #
        # Qt has a clipboard widget but I didn't want to place a QT
        # requirement on using the class since it has nothing to do
        # with the Gui.  TKinter is included with Python.
        #
        r = tkinter.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(strSig)
        r.update()
        r.destroy()

        return True

    def AutoFunction(self) -> bool:
        """
            Generate shortest unique signature possible to current function
        """

        self._reset()

        startea = idc.get_screen_ea()
        if startea in [0, BADADDR]:
            self.__plugin.log('Current ea == BADADDR.', LogOptions.LOG_ERROR)
            return False

        if FUNC_START_EA:
            # Get function start
            func = idaapi.get_func(startea)
            if not func or func.start_ea == BADADDR:
                self.__plugin.log('Must be in a function.', LogOptions.LOG_ERROR)
                return False
            elif startea != func.start_ea:
                startea = func.start_ea
                self.__plugin.log('Using function: 0x%X' % startea, LogOptions.LOG_DEBUG)

        if not self._addRefs(startea):
            return False

        iCount = 0
        bHaveUniqueSig = False

        while not bHaveUniqueSig and len(self.Sigs):

            for sigIndex in range(0, len(self.Sigs)):

                if len(self.Sigs[sigIndex].sig) < self.__plugin.Settings.maxSigLength and self._addToSig(sigIndex):
                    if len(self.Sigs[sigIndex].sig) > 5:
                        self.Sigs[sigIndex].bUnique = BinQuery(' '.join(self.Sigs[sigIndex].sig), QueryTypes.QUERY_UNIQUE)
                else:
                    #return False
                    if sigIndex == 0:
                        self.Sigs = self.Sigs[1:]
                    elif sigIndex == len(self.Sigs) - 1:
                        self.Sigs = self.Sigs[:-1]
                    else:
                        self.Sigs = self.Sigs[:sigIndex] + self.Sigs[sigIndex+1:]

                    sigIndex = sigIndex - 1

            bHaveUniqueSig = self._haveUniqueSig()

        return self._chooseSig()

    def AutoAddress(self) -> bool:
        """
            Rather than create a sig from selection this
            gets current ea from screen and then creates
            the shortest sig possible.

            I don't really see a need for making sigs from a
            selection but can add it if enough people need it.
        """

        self._reset()

        startea = idc.get_screen_ea()
        if startea in [0, BADADDR]:
            self.__plugin.log('Click on address you want sig for.', LogOptions.LOG_ERROR)
            return False

        sig = SigCreateStruct()
        sig.dwStartAddress = startea
        sig.dwCurrentAddress = startea
        sig.eType = PatternType.PT_DIRECT

        self.Sigs.append(sig)

        while not self.Sigs[0].bUnique and len(self.Sigs[0].sig) < self.__plugin.Settings.maxSigLength:

            sigIndex = 0
            if self._addToSig(sigIndex):
                if len(self.Sigs[sigIndex].sig) > 5:
                    self.Sigs[sigIndex].bUnique = BinQuery(' '.join(self.Sigs[sigIndex].sig), QueryTypes.QUERY_UNIQUE)
            else:
                self.__plugin.log('Unable to create sig at selected address', LogOptions.LOG_ERROR)
                return False

        self._chooseSig()

#
#
# QT Gui
#
#
class PluginGui(idaapi.PluginForm):

    def __init__(self, plugin):

        global GUI_DBG_ENABLED

        idaapi.PluginForm.__init__(self)
        self.__plugin = plugin

        if GUI_DBG_ENABLED:
            self._QtDbgHelper = QTDebugHelper(self)
        else:
            self._QtDbgHelper = None

        self.closed = False

    #
    # IDA PluginForm overloaded methods
    #
    def Show(self, caption, options=None):
        if options:
            super().Show(caption, options)
            return
        # Floating window as default.
        super().Show(caption, idaapi.PluginForm.WOPN_DP_FLOATING)

    def OnCreate(self, form):
        self.widget = self.FormToPyQtWidget(form)
        self.PopulateForm()

        # Bit hackish but is needed to restore form position/size.
        # Parent widget isn't set until after this function returns.
        # The passed form is a child under the main TWidget created by IDA
        QtCore.QTimer.singleShot(1000, self._formState)

    def OnClose(self, form):
        self._formState(bSave=True)
        self.closed = True

    #
    # Connected QT events
    #
    def _sigTypeIdaClick(self):
        self.__plugin.Settings.SigType = SigType.SIG_IDA
        self.__plugin.Settings.save()

    def _sigTypeCodeClick(self):
        self.__plugin.Settings.SigType = SigType.SIG_CODE
        self.__plugin.Settings.save()

    def _sigTypeOllyClick(self):
        self.__plugin.Settings.SigType = SigType.SIG_OLLY
        self.__plugin.Settings.save()

    def _sigTest(self):

        patt = self.patt.currentText()
        mask = self.mask.text()

        sig  = ''
        st = GetSigType(patt)

        if st == SigType.SIG_CODE:
            sig = GetIdaSig(patt, mask)
        else:
            sig = GetIdaSig(patt)
            mask = ''

        if not sig:
            self.__plugin.log('Invalid sig: "%s"' % sig, LogOptions.LOG_ERROR)
            return

        self.__plugin.Settings.addHistory(patt, mask)
        self.__plugin.Settings.save()

        query = MakeBin(sig)

        result = BinSearch(query)

        #p, m = MakeBin(sig)
        #ea = BinSearch(p, m)

        #
        # Always logging tests to output so set to LOG_ERROR
        #
        if result != BADADDR:
            self.__plugin.log('Sig matched @ 0x%X' % result.ea, LogOptions.LOG_ERROR)
            #self.__plugin.log('Sig matched @ 0x%X' % ea, LogOptions.LOG_ERROR)
        else:
            self.__plugin.log('No match found', LogOptions.LOG_ERROR)

    def _sigTestSelectChanged(self, index):

        mask = ''
        try:
            mask = self.__plugin.Settings.getHistory()[index][1]
        except:
            pass

        self.mask.setText(mask)

    def _sigCurrentFunction(self):
        self.__plugin.SigMaker.AutoFunction()

    def _sigAtCursor(self):
        self.__plugin.SigMaker.AutoAddress()

    def _logLevelChanged(self, index):
        self.__plugin.Settings.LogLevel = index
        self.__plugin.Settings.save()

    def _sigSelectChanged(self, index):
        self.__plugin.Settings.SigSelect = index
        self.__plugin.Settings.save()

    def _safeDataChecked(self, checkedState):
        #
        # Checkboxes can be tristate so passed arg is not a bool
        #
        if checkedState == QtCore.Qt.Unchecked:
            self.__plugin.Settings.bOnlyReliable = False
        else:
            self.__plugin.Settings.bOnlyReliable = True

        self.__plugin.Settings.save()

    def _archiveSigmaker(self):

        global PLUGIN_DIR, HOTKEY_CONFLICT, SIGMAKER_X64_PLUGINS

        bDidMove = False

        for name in SIGMAKER_X64_PLUGINS:

            if not os.path.exists('%s/orig_sigmaker' % PLUGIN_DIR):
                self.__plugin.log('mkdir: %s/orig_sigmaker' % (PLUGIN_DIR), LogOptions.LOG_ERROR)
                os.mkdir('%s/orig_sigmaker' % PLUGIN_DIR)

            if os.path.isfile('%s/%s' % (PLUGIN_DIR, name)):
                shutil.move('%s/%s' % (PLUGIN_DIR, name), '%s/orig_sigmaker/%s' % (PLUGIN_DIR, name))
                bDidMove = True
                self.__plugin.log('Moved: %s/%s to %s/orig_sigmaker/%s' % (PLUGIN_DIR, name, PLUGIN_DIR, name), LogOptions.LOG_ERROR)

        if bDidMove:
            self.__plugin.log('SigMaker-x64 archived, restart IDA to unload it', LogOptions.LOG_ERROR)
            HOTKEY_CONFLICT = False
            SIGMAKER_X64_PLUGINS = []
            self.archiveBtn.setEnabled(False)

    def _saveHotkey(self):
        hotkey = self.hotkeyTxt.text()
        if hotkey != self.__plugin.Settings.hotkey:
            self.__plugin.Settings.hotkey = hotkey
            self.__plugin.Settings.save()
            self.__plugin.log('\npySigMaker hotkey changed to %s, IDA restart needed.' % hotkey, LogOptions.LOG_ERROR)

    def _defaultHotkey(self):
        global PLUGIN_HOTKEY
        self.hotkeyTxt.setText(PLUGIN_HOTKEY)
        if PLUGIN_HOTKEY != self.__plugin.Settings.hotkey:
            self.__plugin.Settings.hotkey = PLUGIN_HOTKEY
            self.__plugin.Settings.save()
            self.__plugin.log('\npySigMaker hotkey changed to %s (default), IDA restart needed.' % PLUGIN_HOTKEY, LogOptions.LOG_ERROR)

    #
    # Save/Restore plugin form position and size.
    #
    def _formState(self, bSave=False):

        def getWidget():
            widget, parent = None, self.widget
            while parent:
                if parent.windowTitle() == self.widget.windowTitle():
                    widget = parent
                parent = parent.parent()
            return widget

        widget = getWidget()
        if not widget:
            self.__plugin.log('Failed to save form info', LogOptions.LOG_ERROR)
            return

        if bSave:
            qrect = widget.geometry()
            x, y, w, h = qrect.x(), qrect.y(), qrect.width(), qrect.height()
            self.__plugin.Settings.saveFormInfo(x, y, w, h)
            self.__plugin.Settings.save()
            self.__plugin.log('Form saved, x={}, y={}, w={}, h={}'.format(x, y, w, h), LogOptions.LOG_DEBUG)
        else:
            x, y, w, h = self.__plugin.Settings.getFormInfo()
            if x > -1:
                widget.setGeometry(x, y, w, h)
                self.__plugin.log('Form restored: x={}, y={}, w={}, h={}'.format(x, y, w, h), LogOptions.LOG_DEBUG)
            self.patt.setCurrentText('')

    #
    # QT widget creation
    #
    def _getSigTypesBox(self):
        """ Sig type selector"""

        setting = self.__plugin.Settings.SigType

        grp = QtWidgets.QGroupBox("Sig Type")

        r1 = QtWidgets.QRadioButton(" IDA ")
        r2 = QtWidgets.QRadioButton(" Code ")
        r3 = QtWidgets.QRadioButton(" Olly ")

        r1.toggled.connect(self._sigTypeIdaClick)
        r2.toggled.connect(self._sigTypeCodeClick)
        r3.toggled.connect(self._sigTypeOllyClick)

        if setting == SigType.SIG_IDA:
            r1.setChecked(True)
        elif setting == SigType.SIG_CODE:
            r2.setChecked(True)
        elif setting == SigType.SIG_OLLY:
            r3.setChecked(True)

        layout = QtWidgets.QHBoxLayout()
        layout.addWidget(r1)
        layout.addWidget(r2)
        layout.addWidget(r3)

        grp.setLayout(layout)

        return grp

    def _initSettings(self, layout):

        global HOTKEY_CONFLICT

        formLayout = QtWidgets.QFormLayout()
        #
        # Log to output window options
        #
        self.logOpt = QtWidgets.QComboBox()
        for s in ['Errors', 'Errors/Results', 'Debug']:
            self.logOpt.addItem(s)

        if self.__plugin.Settings.LogLevel > LogOptions.LOG_DEBUG:
            self.__plugin.Settings.LogLevel = LogOptions.LOG_DEBUG
        elif self.__plugin.Settings.LogLevel < LogOptions.LOG_ERROR:
            self.__plugin.Settings.LogLevel = LogOptions.LOG_ERROR

        self.logOpt.setCurrentIndex(self.__plugin.Settings.LogLevel)
        self.logOpt.currentIndexChanged.connect(self._logLevelChanged)

        #
        # Selecting sig from results options
        #
        self.sigSelectorOpt = QtWidgets.QComboBox()
        for s in ['Shortest Sig', 'Least Opcodes', 'Least Wildcards']:
            self.sigSelectorOpt.addItem(s)

        if self.__plugin.Settings.SigSelect > SigSelect.OPT_WILDCARDS:
            self.__plugin.Settings.SigSelect = SigSelect.OPT_WILDCARDS
        elif self.__plugin.Settings.SigSelect < SigSelect.OPT_LENGTH:
            self.__plugin.Settings.SigSelect = SigSelect.OPT_LENGTH

        self.sigSelectorOpt.setCurrentIndex(self.__plugin.Settings.SigSelect)
        self.sigSelectorOpt.currentIndexChanged.connect(self._sigSelectChanged)

        #
        # Reliable/Unreliable data option
        #
        self.safeData = QtWidgets.QCheckBox()
        self.safeData.setTristate(False)

        if self.__plugin.Settings.bOnlyReliable:
            self.safeData.setCheckState(QtCore.Qt.Checked)
        else:
            self.safeData.setCheckState(QtCore.Qt.Unchecked)

        self.safeData.stateChanged.connect(self._safeDataChecked)

        if HOTKEY_CONFLICT:
            self.archiveBtn = QtWidgets.QPushButton('Archive SigMaker-x64')
            self.archiveBtn.clicked.connect(self._archiveSigmaker)

        formLayout.addRow('Output', self.logOpt)
        formLayout.addRow('Sig Choice', self.sigSelectorOpt)
        formLayout.addRow('Reliable Data Only', self.safeData)

        layout.addLayout(formLayout)

        layout2 = QtWidgets.QHBoxLayout()

        lbl = QtWidgets.QLabel('Hotkey:')

        self.hotkeyTxt = QtWidgets.QLineEdit()
        self.hotkeyTxt.setText(self.__plugin.Settings.hotkey)
        self.hotkeySetBtn = QtWidgets.QPushButton('Set')
        self.hotkeyRestoreBtn = QtWidgets.QPushButton('Default')
        self.hotkeySetBtn.clicked.connect(self._saveHotkey)
        self.hotkeyRestoreBtn.clicked.connect(self._defaultHotkey)

        layout2.addWidget(lbl)
        layout2.addWidget(self.hotkeyTxt)
        layout2.addWidget(self.hotkeySetBtn)
        layout2.addWidget(self.hotkeyRestoreBtn)

        layout.addLayout(layout2)

        if HOTKEY_CONFLICT:
            layout.addWidget(self.archiveBtn)

    def _initMainTab(self):

        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        btn1 = QtWidgets.QPushButton('  Sig for current function  ')
        btn2 = QtWidgets.QPushButton('  Sig at current cursor position  ')

        btn1.clicked.connect(self._sigCurrentFunction)
        btn2.clicked.connect(self._sigAtCursor)

        layout.addWidget(btn1)
        layout.addWidget(btn2)
        layout.addWidget(self._getSigTypesBox())

        tab.setLayout(layout)
        self.tabControl.addTab(tab, 'Create Sigs')

    def _initSigTest(self):

        tab = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout()

        # Need refs to patt and mask controls
        self.patt = QtWidgets.QComboBox()
        self.patt.setEditable(True)
        self.patt.setCurrentText("")

        self.mask = QtWidgets.QLineEdit()
        self.mask.setText("")

        self.patt.setInsertPolicy(QtWidgets.QComboBox.NoInsert)

        sigs = [ x[0] for x in self.__plugin.Settings.getHistory() ]
        self.patt.addItems(sigs)

        btn = QtWidgets.QPushButton(' Test ')
        btn.clicked.connect(self._sigTest)

        self.patt.currentIndexChanged.connect(self._sigTestSelectChanged)

        layout.addRow('Patt', self.patt)
        layout.addRow('Mask', self.mask)
        layout.addRow('', btn)

        tab.setLayout(layout)
        self.tabControl.addTab(tab, 'Test Sigs')

    def _initSettingsTab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        self._initSettings(layout)
        tab.setLayout(layout)
        self.tabControl.addTab(tab, 'Settings')

    def PopulateForm(self):

        layout = QtWidgets.QVBoxLayout()
        self.tabControl = QtWidgets.QTabWidget(self.widget)
        layout.addWidget(self.tabControl)
        self.widget.setLayout(layout)

        self._initMainTab()
        self._initSigTest()
        self._initSettingsTab()

        if self._QtDbgHelper:
           self._QtDbgHelper.initDebugTab()

        return


#
# Shared settings class
#
class PluginSettings:

    def __init__(self, plugin):

        global PLUGIN_HOTKEY

        self.__plugin     = plugin
        self.__loaded     = False
        self.__configName = idaapi.get_user_idadir() + '\\pySigMaker.config'

        # 0 disables limit
        self.maxRefs = 0

        # False creates less reliable sigs IE: they break easier on updates
        self.bOnlyReliable = True

        # Controls how sig is selected from multiple unique sigs
        self.SigSelect = SigSelect.OPT_LENGTH

        # Type of sig to return
        self.SigType = SigType.SIG_IDA

        self.LogLevel = LogOptions.LOG_ERROR

        # Max sig length IE: 'E9 ?' is length of 2
        self.maxSigLength = 100

        # Sig test history
        self._history = []

        # default hot key
        self.hotkey = PLUGIN_HOTKEY

        # form info
        self.x = -1
        self.y = -1
        self.w = -1
        self.h = -1

    def saveFormInfo(self, x, y, w, h):
        self.x = x
        self.y = y
        self.w = w
        self.h = h

    def getFormInfo(self):
        return self.x, self.y, self.w, self.h

    def getHistory(self):
        return self._history

    def addHistory(self, sig, mask=''):

        # Move to front of list when used, limit history to last 10 entries
        hist = [[sig, mask]]

        for p, m in self._history:
            if p == sig:
                continue
            hist.append([p, m])
            if len(hist) == 10:
                break

        self._history = hist

    def load(self):

        if self.__loaded:
            return

        if not os.path.exists(self.__configName):
            self.__plugin.log('pySigMaker: Using defaults', LogOptions.LOG_ERROR)
            return False

        if not os.path.isfile(self.__configName):
            self.__plugin.log('pySigMaker: Using defaults', LogOptions.LOG_ERROR)
            return False


        d  = {}
        fh = None

        try:
            fh = open(self.__configName, 'rb')
            d = pickle.load(fh)
        except:
            self.__plugin.log('pySigMaker: Cfg corrupt, using defaults', LogOptions.LOG_ERROR)

        if fh:
            fh.close()

        for k, v in d.items():
            if k in self.__dict__:
                self.__dict__[k] = v
                self.__plugin.log('cfg-load: {0} {1} {2}'.format(k, v, type(v)), LogOptions.LOG_DEBUG)

        self.__loaded = True
        return d != {}

    def save(self):

        d = {}
        for k, v in self.__dict__.items():
            if k.find('__') > -1:
                continue
            d[k] = v
            self.__plugin.log('cfg-save: {0} {1} {2}'.format(k, v, type(v)), LogOptions.LOG_DEBUG)

        fh = None

        try:
            fh = open(self.__configName, 'wb')
            pickle.dump(d, fh)
        except:
            self.__plugin.log('pySigMaker: Failed to save config', LogOptions.LOG_ERROR)

        if fh:
            fh.close()

class SigMakerPlugin:

    def __init__(self):
        self.Settings = PluginSettings(self)
        self.Gui = PluginGui(self)
        self.SigMaker = SigMaker(self)
        self.Settings.load()

    def log(self, msg, log_level = LogOptions.LOG_RESULT):
        if log_level == LogOptions.LOG_ERROR or log_level <= self.Settings.LogLevel:
            print(msg)

    def showGui(self):
        if not self.Gui or self.Gui.closed:
            self.Gui = PluginGui(self)
        self.Gui.Show('pySigMaker')

def banner(hotkey):
    print('---------------------------------------------------------------------------------------------')
    print('pySigMaker: zoomgod - unknowncheats.me (credit to ajkhoury for origional SigMaker-X64 code)')
    print('            v%s - hotkey: %s' % (PLUGIN_VERSION, hotkey))
    print('---------------------------------------------------------------------------------------------')

#
# IDA Plugin Loader
#

gsigmaker = SigMakerPlugin()
banner(gsigmaker.Settings.hotkey)

def PLUGIN_ENTRY():
    return sigmaker_t()

class sigmaker_t(idaapi.plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = 'Creates code signature patterns.'
    help = ''
    wanted_name = 'pySigMaker'
    wanted_hotkey = gsigmaker.Settings.hotkey

    def init(self):
        global gsigmaker
        if not gsigmaker:
            gsigmaker = SigMakerPlugin()
        return idaapi.PLUGIN_KEEP

    def run(self, arg=None):
        global gsigmaker
        if not gsigmaker:
            gsigmaker = SigMakerPlugin()
        gsigmaker.showGui()

    def term(self):
        global gsigmaker
        gsigmaker = None
