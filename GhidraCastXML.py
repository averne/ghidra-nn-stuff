# Import CastXML fiiles into Ghidra.
#@author aerosoul github.com/aerosoul94
#@category Data Types
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.data import FileDataTypeManager
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.data import Undefined
from ghidra.program.model.data import BadDataType

from ghidra.program.model.data import AbstractDataType
from ghidra.program.model.data import FloatDataType
from ghidra.program.model.data import CharDataType
from ghidra.program.model.data import ShortDataType
from ghidra.program.model.data import LongDataType
from ghidra.program.model.data import LongLongDataType
from ghidra.program.model.data import BooleanDataType
from ghidra.program.model.data import DoubleDataType
from ghidra.program.model.data import LongDoubleDataType
from ghidra.program.model.data import SignedCharDataType
from ghidra.program.model.data import IntegerDataType
from ghidra.program.model.data import Integer16DataType
from ghidra.program.model.data import UnsignedCharDataType
from ghidra.program.model.data import UnsignedShortDataType
from ghidra.program.model.data import UnsignedIntegerDataType
from ghidra.program.model.data import UnsignedInteger16DataType
from ghidra.program.model.data import UnsignedLongDataType
from ghidra.program.model.data import UnsignedLongLongDataType
from ghidra.program.model.data import WideCharDataType
from ghidra.program.model.data import WideChar16DataType
from ghidra.program.model.data import WideChar32DataType
from ghidra.program.model.data import VoidDataType

from ghidra.program.model.data import GenericDataType
from ghidra.program.model.data import GenericCallingConvention
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import ArrayDataType
from ghidra.program.model.data import ParameterDefinitionImpl
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.data import UnionDataType
from ghidra.program.model.data import EnumDataType
from ghidra.program.model.data import TypedefDataType
from ghidra.program.model.data import CategoryPath
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.data import FunctionDefinition

from java.io import File
from java.lang import Exception as JavaException

import xml.etree.ElementTree as ET
import traceback
import os, sys


class GhidraCastXMLLoader:
    """
    CastXML importer class
    """

    class TypeInfo:
        """
        Maps CastXML XML element to a Ghidra DataType
        """
        def __init__(self, element, dataType=None):
            self.element = element
            self.dataType = dataType

        def getElement(self):
            return self.element

        def setDataType(self, dataType):
            self.dataType = dataType

        def getDataType(self):
            return self.dataType

        def hasDataType(self):
            return self.dataType != None


    def __init__(self, outputGDT):
        """
        Initialize importer attributes

        Args:
            outputGDT (str): Output GDT file
        """
        self.output = outputGDT # (str): output GDT file
        self.transaction = None
        self.input = None
        self.dtMgr = None
        self.xml = None
        self.root = None
        self.defaultPointerSize = getCurrentProgram().getDefaultPointerSize()
        self.selectedFiles = []
        self.types = {}
        self.files = {}
        self.namespaces = {}
        self.fundamentalTypes = {}


    def importXML(self, inputXML):
        """
        Import inputXML as Ghidra Data Types

        Args:
            inputXML (str): Input CastXML path
        """
        self.dtMgr = FileDataTypeManager.createFileArchive(File(self.output))

        self.loadXML(inputXML)
        self.importAllTypes()

        self.dtMgr.save()


    def loadXML(self, inputXML):
        """
        Load all elements and creates TypeInfo for each potential type.

        Args:
            inputXML (str): Input CastXML XML path
        """
        self.xml = ET.parse(inputXML)
        self.root = self.xml.getroot()

        for element in self.root:
            id = element.attrib['id']
            if element.tag == "File":
                self.files[id] = element
            else:
                self.types[id] = self.TypeInfo(element)

        # Choose which files to include.
        # This will
        #choices = [x.attrib['id'] for x in self.files.values()]
        #choiceLabels = [x.attrib['name'] for x in self.files.values()]
        #self.selectedFiles = askChoices("Multiple Files", "Choose which header files to import.", choices, choiceLabels)
        #print self.selectedFiles


    def importAllTypes(self):
        """
        Does the XML importing work.
        """
        self.transation = self.dtMgr.startTransaction("")

        loadableTypes = (
            # Composite
            "Class",
            "Struct",
            "Union",
            # Typedefs
            "Typedef",
            # Enums
            "Enumeration",
            # Functions
            "Function",
            "Method",
            # Namespaces
            "Namespace"
        )

        print("Loading...")
        for element in self.root:
            if element.tag in loadableTypes:
                    # and element.attrib['file'] in self.selectedFiles:
                dataType = self.getDataType(element)
                if dataType != None:
                    self.dtMgr.resolve(dataType, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER)
        print("Done.")

        self.dtMgr.endTransaction(self.transation, True)
        self.transaction = None


    def close(self):
        """
        Cleanup if ended abrubtly and close the DataTypeManager.
        """
        if self.transaction != None:
            self.dtMgr.endTransaction(self.transaction, True)
        if self.dtMgr != None:
            self.dtMgr.close()


    def getDefaultPointerSize(self):
        """
        Get the current default pointer bit size. By default it is set to
        getCurrentProgram().getDefaultPointerSize(), however it can be overridden
        using setDefaultPointerSize().

        Returns: the default pointer size in bits
        """
        return self.defaultPointerSize


    def setDefaultPointerSize(self, defaultPointerSize):
        """
        Override default pointer size. This was used for testing.

        Args:
            defaultPointerSize (int): default pointer size in bits
        """
        self.defaultPointerSize = defaultPointerSize


    def getTypeInfoById(self, id):
        """
        Get TypeInfo instance from types.

        Args:
            id (str): XML element id

        Returns (TypeInfo): TypeInfo instance for this id
        """
        return self.types[id]


    def getTypeInfoElementById(self, id):
        """
        Get XML Element for this id.

        Args:
            id (str): XML element id

        Returns (ElementTree): XML element
        """
        return self.types[id].getElement()


    def getTypeInfoDataTypeById(self, id):
        """
        Get DataType for this id.

        Args:
            id (str): XML element id

        Returns (DataType): Ghidra DataType
        """
        return self.types[id].getDataType()


    def getNamespaceById(self, id):
        try:
            return self.namespaces[id]
        except KeyError:
            return ""


    def recordTypeForId(self, id, dataType):
        """
        Set DataType for this id.

        Args:
            id (str): XML element id
        """
        self.types[id].setDataType(dataType)


    def recordNamespace(self, element):
        name = element.attrib["name"]

        try:
            context = element.attrib["context"]
            name = self.getNamespaceById(context) + name + "::"
        except KeyError:
            pass

        if name == "::":
            name = ""

        self.namespaces[element.attrib["id"]] = name

        print("Namespace: {}".format(name))


    def getNameForElement(self, element):
        return element.attrib["name"]
        # try:
        #     return self.getNamespaceById(element.attrib["context"]) + element.attrib["name"]
        # except KeyError:
        #     return element.attrib["name"]


    def getFileFromId(self, id):
        """
        Get file path for this id. See "File" elements.

        Args:
            id (str): XML element id

        Returns (str): file path
        """
        fileElement = self.files[id]
        return fileElement.attrib['name']


    def getCategoryPathFromFile(self, filePath):
        """
        Generate a CategoryPath from a filePath. This uses the file name as
        the CategoryPath.

        Args:
            filePath (str): file path for this data type

        Returns (CategoryPath): Category path for this data type
        """
        # make sure we use the same path separators
        filePath = filePath.replace("/", "\\")
        categoryPath = "/" + filePath.split("\\")[-1]
        #print categoryPath
        return CategoryPath(categoryPath)


    def createEnumeration(self, element):
        """
        Convert CastXML XML element into a Ghidra EnumDataType.

        Args:
            element (ElementTree): XML element

        Returns (EnumDataType): Ghidra EnumDataType
        """
        enumName = self.getNameForElement(element)
        if enumName == "":
            enumName = "anon_enum" + element.attrib['id']

        print("Enum: {0}".format(enumName))

        enumBitSize = int(element.attrib['size'])
        enumByteSize = enumBitSize / 8

        filePath = self.getFileFromId(element.attrib['file'])
        categoryPath = self.getCategoryPathFromFile(filePath)

        enumDataType = EnumDataType(categoryPath, enumName, enumByteSize)
        for enumValue in element:
            name = self.getNameForElement(enumValue)
            bitSize = int(element.attrib['size'])
            init = int(enumValue.attrib['init'])

            #print("{0} = {1}".format(name, init))

            # Convert to signed integer as Java cannot coerce large unsigned numbers
            init = init & ((1 << bitSize) - 1)
            init = init | (-(init & (1 << (bitSize - 1))))

            enumDataType.add(name, init)

        self.recordTypeForId(element.attrib['id'], enumDataType)
        self.recordNamespace(element)

        return enumDataType


    def createStructure(self, element):
        """
        Convert CastXML XML element into a Ghidra StructureDataType.

        Args:
            element (ElementTree): XML element

        Returns (StructureDataType): Ghidra StructureDataType
        """
        structName = ""
        if 'name' in element.attrib:
            structName = self.getNameForElement(element)
        if structName == "":
            structName = "anon_struct" + element.attrib['id']

        structByteSize = 0
        if 'size' in element.attrib:
            structBitSize = int(element.attrib['size'])
            structByteSize = structBitSize / 8

        structAlign = 0
        if 'align' in element.attrib:
            structAlign = int(element.attrib['align']) / 8

        filePath = self.getFileFromId(element.attrib['file'])
        categoryPath = self.getCategoryPathFromFile(filePath)

        print("Struct: {0}".format(structName))

        structureDataType = StructureDataType(categoryPath, structName, structByteSize, self.dtMgr)

        # These will allow Ghidra to pack and align our data types to our program's specs.
        # Unused for now. Let's respect what we have from CastXML.
        #structureDataType.setMinimumAlignment(structAlign)
        #structureDataType.setPackingValue(structAlign)

        self.recordTypeForId(element.attrib['id'], structureDataType)
        self.recordNamespace(element)

        # Load all base classes
        if 'bases' in element.attrib:
            baseElements = element.getchildren()
            for i, baseElement in enumerate(baseElements):
                baseTypeElement = self.getTypeInfoElementById(baseElement.attrib['type'])
                baseType = self.getDataType(baseTypeElement)
                baseOffset = 0
                if 'offset' in baseElement.attrib:
                    baseOffset = int(baseElement.attrib['offset'])
                baseName = "base" + str(i) + "_" + str(baseOffset)
                baseLength = baseType.getLength()
                structureDataType.replaceAtOffset(baseOffset, baseType, baseLength, baseName, hex(baseOffset))

        # Add VTable pointer
        if 'abstract' in element.attrib and 'bases' not in element.attrib:
            if int(element.attrib['abstract']) == 1:
                # TODO: generate vtable structure
                pointerLength = self.getDefaultPointerSize()
                pointerType = PointerDataType(VoidDataType(), pointerLength)
                structureDataType.replaceAtOffset(0, pointerType, pointerType.getLength(), "vtable", hex(0))

        # Add each field
        if 'members' in element.attrib:
            members = element.attrib['members']
            memberIds = members.split(" ")
            bitFieldOffset = -1 # -1 = not set
            bitFieldTotalSize = 0
            for memberId in memberIds:
                fieldElement = self.getTypeInfoElementById(memberId)
                if fieldElement.tag != "Field":
                    continue

                typeElement = self.getTypeInfoElementById(fieldElement.attrib['type'])

                fieldName = self.getNameForElement(fieldElement)
                fieldOffset = int(fieldElement.attrib['offset']) / 8
                if fieldOffset >= structByteSize:
                    continue

                # TODO: check if at end of structure and check if structure already has flexible array
                if typeElement.tag == "ArrayType" and int(typeElement.attrib['max']) == -1:
                    # TODO: check if valid arrayDataType
                    arrayElement = self.getTypeInfoElementById(typeElement.attrib['type'])
                    arrayDataType = self.getDataType(arrayElement)
                    structureDataType.setFlexibleArrayComponent(arrayDataType, fieldName, hex(fieldOffset))
                else:
                    fieldDataType = self.getDataType(typeElement)
                    if 'bits' in fieldElement.attrib:
                        # This is a bitfield
                        byteOffset = fieldOffset

                        if bitFieldOffset == -1:
                            # Store first bitfield byteOffset
                            bitFieldOffset = fieldOffset * 8

                        byteWidth = structureDataType.getLength() - (bitFieldOffset / 8) #fieldDataType.getLength()
                        bitFieldTotalSize = byteWidth * 8

                        bitOffset = int(fieldElement.attrib['offset']) - bitFieldOffset
                        bitSize = int(fieldElement.attrib['bits'])

                        try:
                            structureDataType.insertBitFieldAt(bitFieldOffset / 8, byteWidth, bitOffset, fieldDataType, bitSize, fieldName, hex(bitOffset) + " bits")
                        except JavaException as e:
                            print structName + " -> " + fieldName
                            print "Current bitfield range: " + str(bitOffset) + " - " + str(bitOffset + bitSize)
                            print "bitFieldOffset: " + str(bitFieldOffset)
                            print "bitFieldTotalSize: " + str(bitFieldTotalSize)
                            print "bitFieldDataType: " + str(fieldDataType)
                            print "bitFieldDataTypeSize: " + str(fieldDataType.getLength())
                            print "byteOffset: " + str(byteOffset)
                            print "byteWidth: " + str(byteWidth)
                            print "bitOffset: " + str(bitOffset)
                            print "bitSize: " + str(bitSize)
                            print e

                        if (bitOffset + bitSize) >= bitFieldTotalSize:
                            # This should be the last bitfield
                            bitFieldOffset = -1
                            bitFieldTotalSize = 0
                    else:
                        structureDataType.replaceAtOffset(fieldOffset, fieldDataType, fieldDataType.getLength(), fieldName, hex(fieldOffset) + " bytes")

        return structureDataType


    def createUnion(self, element):
        """
        Convert CastXML XML element into a Ghidra UnionDataType.

        Args:
            element (ElementTree): XML element

        Returns (UnionDataType): Ghidra UnionDataType
        """
        unionName = ""
        if 'name' in element.attrib:
            unionName = self.getNameForElement(element)
        if unionName == "":
            unionName = "anon_union" + element.attrib['id']

        print("Union: {0}".format(unionName))

        unionByteSize = 0
        if 'size' in element.attrib:
            unionBitSize = int(element.attrib['size'])
            unionByteSize = unionBitSize / 8

        unionAlign = 0
        if 'align' in element.attrib:
            unionAlign = int(element.attrib['align']) / 8

        filePath = self.getFileFromId(element.attrib['file'])
        categoryPath = self.getCategoryPathFromFile(filePath)

        unionDataType = UnionDataType(categoryPath, unionName, self.dtMgr)

        self.recordTypeForId(element.attrib['id'], unionDataType)

        if 'members' in element.attrib:
            members = element.attrib['members']
            memberIds = members.split(" ")
            for memberId in memberIds:
                memberElement = self.getTypeInfoElementById(memberId)
                if memberElement.tag != "Field":
                    continue

                fieldElement = self.getTypeInfoElementById(memberElement.attrib['type'])
                fieldName = self.getNameForElement(memberElement)
                fieldDataType = self.getDataType(fieldElement)
                fieldOffset = int(memberElement.attrib['offset']) / 8

                unionDataType.add(fieldDataType, fieldName, hex(fieldOffset))

        if unionDataType.getLength() < unionByteSize:
            padding = Undefined.getUndefinedDataType(unionByteSize)
            unionDataType.add(padding, None, "Padding to match true size")

        return unionDataType


    def createFunction(self, element):
        """
        Convert CastXML XML element into a Ghidra FunctionDefinitionDataType.

        Args:
            element (ElementTree): XML element

        Returns (FunctionDefinitionDataType): Ghidra FunctionDefinitionDataType
        """
        functionName = ""
        if 'name' in element.attrib:
            functionName = self.getNameForElement(element)
        else:
            functionName = "anon_func" + element.attrib['id']

        print("Function: {0}".format(functionName))

        functionType = None
        if 'file' in element.attrib:
            filePath = self.getFileFromId(element.attrib['file'])
            categoryPath = self.getCategoryPathFromFile(filePath)
            functionType = FunctionDefinitionDataType(categoryPath, functionName)
        else:
            functionType = FunctionDefinitionDataType(functionName)

        returnTypeElement = self.getTypeInfoElementById(element.attrib['returns'])
        returnType = self.getDataType(returnTypeElement)
        functionType.setReturnType(returnType)

        parms = []
        argumentElements = element.getchildren()
        for i, argumentElement in enumerate(argumentElements):
            if argumentElement.tag == "Argument":
                argumentName = ""
                if 'name' in argumentElement.attrib:
                    argumentName = self.getNameForElement(argumentElement)
                else:
                    argumentName = "a" + str(i)

                argumentTypeElement = self.getTypeInfoElementById(argumentElement.attrib['type'])
                parmDataType = self.getDataType(argumentTypeElement)

                parms.append(ParameterDefinitionImpl(argumentName, parmDataType, ""))
            elif argumentElement.tag == "Elipsis":
                functionType.setVarArgs(True)

        functionType.setArguments(parms)

        self.recordTypeForId(element.attrib['id'], functionType)

        return functionType


    def createMemberFunction(self, element):
        functionType = self.createFunction(element)
        functionType.setGenericCallingConvention(GenericCallingConvention.thiscall)
        return functionType


    def createTypedef(self, element):
        """
        Convert CastXML XML element into a Ghidra TypedefDataType.

        Args:
            element (ElementTree): XML element

        Returns (TypedefDataType): Ghidra TypedefDataType
        """
        typedefName = ""
        if 'name' in element.attrib:
            typedefName = self.getNameForElement(element)
        if typedefName == "":
            typedefName = "anon_typedef" + element.attrib['id']

        print("Typedef: {0}".format(typedefName))

        underlyingTypeElement = self.getTypeInfoElementById(element.attrib['type'])
        underlyingDataType = self.getDataType(underlyingTypeElement)
        if underlyingDataType == None:
            # Since we failed to retrieve a valid type, we will default to Undefined.
            underlyingDataType = Undefined.getUndefinedDataType(1)
            print "Invalid DataType returned for Typedef: tag={0} id={1}".format(underlyingTypeElement.tag, underlyingTypeElement.attrib['id'])

        filePath = self.getFileFromId(element.attrib['file'])
        categoryPath = self.getCategoryPathFromFile(filePath)

        typedefDataType = TypedefDataType(categoryPath, typedefName, underlyingDataType)

        self.recordTypeForId(element.attrib['id'], typedefDataType)

        return typedefDataType


    def createPointer(self, element):
        """
        Convert CastXML XML element into a Ghidra PointerDataType.

        Args:
            element (ElementTree): XML element

        Returns (PointerDataType): Ghidra PointerDataType
        """
        pointeeElement = self.getTypeInfoElementById(element.attrib['type'])
        dataType = self.getDataType(pointeeElement)
        if dataType == None:
            dataType = Undefined.getUndefinedDataType(1)
            print "Invalid DataType returned for PointerType: tag={0} id={1}".format(pointeeElement.tag, pointeeElement.attrib['id'])
        pointerLength = self.getDefaultPointerSize()
        if 'size' in element.attrib:
            pointerLength = int(element.attrib['size']) / 8
        pointerType = PointerDataType(dataType, pointerLength)

        self.recordTypeForId(element.attrib['id'], pointerType)

        return pointerType


    def createArray(self, element):
        """
        Convert CastXML XML element into a Ghidra ArrayDataType.

        Args:
            element (ElementTree): XML element

        Returns (ArrayDataType): Ghidra ArrayDataType
        """
        arrayTypeElement = self.getTypeInfoElementById(element.attrib['type'])
        dataType = self.getDataType(arrayTypeElement)
        if dataType == None:
            print arrayTypeElement.tag

        maxIndex = minIndex = 0
        if element.attrib['max'] != "":
            maxIndex = int(element.attrib['max'])
        if element.attrib['min'] != "":
            minIndex = int(element.attrib['min'])

        elementLength = dataType.getLength()
        numElements = (maxIndex - minIndex) + 1

        if numElements == 0:
            # FIXME: Ghidra won't accept 0 size arrays
            # Setting it to 1 would consume more bytes than it may actually exist as.
            # e.g. struct foobar baz[0]
            return Undefined.getUndefinedDataType(1)
            #numElements = 1

        arrayDataType = ArrayDataType(dataType, numElements, elementLength)
        self.recordTypeForId(element.attrib['id'], arrayDataType)
        return arrayDataType


    def getIntType(self, isUnsigned, size):
        """
        Get int DataType based on whether the type is unsigned or not, and
        on its bit size.

        Args:
            isUnsigned (bool): whether or not you need an unsigned type
            size (int): size of the int in bits

        Returns (DataType): Int DataType or None
        """
        if isUnsigned == True:
            if size == 16:
                return UnsignedShortDataType()
            elif size == 32:
                return UnsignedIntegerDataType()
            elif size == 128:
                return UnsignedInteger16DataType()
        else:
            if size == 16:
                return ShortDataType()
            elif size == 32:
                return IntegerDataType()
            elif size == 128:
                return Integer16DataType()

        return None


    def getLongType(self, isUnsigned, size):
        """
        Get long DataType based on whether the type is unsigned or not, and
        on its bit size.

        Args:
            isUnsigned (bool): whether or not you need an unsigned type
            size (int): size of the long in bits

        Returns (DataType): Long DataType or None
        """
        if isUnsigned == True:
            if size == 32:
                return UnsignedLongDataType()
            elif size == 64:
                return UnsignedLongLongDataType()
        else:
            if size == 32:
                return LongDataType()
            elif size == 64:
                return LongLongDataType()

        return None


    def getFundamentalType(self, element):
        """
        Get a fundamental Ghidra DataType from this CastXML element.

        Args:
            element (ElementTree): XML element

        Returns (DataType): fundamental Ghidra DataType
        """
        typeName = element.attrib['name']
        typeSize = int(element.attrib['size'])
        if typeName not in self.fundamentalTypes:
            # add type to fundamentalTypes
            fundamentalType = None
            if typeName == "void":
                fundamentalType = VoidDataType()
            elif typeName == "bool":
                fundamentalType = BooleanDataType()
            elif typeName == "char":
                fundamentalType = CharDataType()
            elif typeName == "signed char":
                fundamentalType = SignedCharDataType()
            elif typeName == "unsigned char":
                fundamentalType = UnsignedCharDataType()
            elif typeName == "wchar_t":
                fundamentalType = WideCharDataType()
            elif typeName == "char16_t":
                fundamentalType = WideChar16DataType()
            elif typeName == "char32_t":
                fundamentalType = WideChar32DataType()
            elif typeName in ("long int", "long long int",):
                fundamentalType = self.getLongType(False, typeSize)
            elif typeName in ("long unsigned int",  "long long unsigned int"):
                fundamentalType = self.getLongType(True, typeSize)
            elif typeName in ("short int", "int", "__int128"):
                fundamentalType = self.getIntType(False, typeSize)
            elif typeName in ("short unsigned int", "unsigned int", "unsigned __int128"):
                fundamentalType = self.getIntType(True, typeSize)
            elif typeName == "float":
                fundamentalType = FloatDataType()
            elif typeName == "double":
                fundamentalType = DoubleDataType()
            elif typeName == "long double":
                fundamentalType = LongDoubleDataType()
            elif typeName == "decltype(nullptr)":
                fundamentalType = PointerDataType()
            else:
                raise Exception("Unhandled fundamental type: " + typeName)

            self.fundamentalTypes[typeName] = fundamentalType

            return fundamentalType

        return self.fundamentalTypes[typeName]


    def getDataType(self, element):
        """
        Convert CastXML XML element into a Ghidra DataType.

        Args:
            element (ElementTree): XML element

        Returns (DataType): Ghidra DataType
        """
        dataType = self.getTypeInfoDataTypeById(element.attrib['id'])
        if dataType != None:
            return dataType

        if element.tag == "FundamentalType":
            dataType = self.getFundamentalType(element)
        elif element.tag == "CvQualifiedType":
            qtype = self.getTypeInfoElementById(element.attrib['type'])
            dataType = self.getDataType(qtype)
        elif element.tag == "PointerType" or element.tag == "ReferenceType":
            dataType = self.createPointer(element)
        elif element.tag == "ArrayType":
            dataType = self.createArray(element)
        elif element.tag == "ElaboratedType":
            elem = self.getTypeInfoElementById(element.attrib['type'])
            dataType = self.getDataType(elem)
        elif element.tag == "Typedef":
            dataType = self.createTypedef(element)
        elif element.tag == "Class" or element.tag == "Struct":
            dataType = self.createStructure(element)
        elif element.tag == "Union":
            dataType = self.createUnion(element)
        elif element.tag == "Enumeration":
            dataType = self.createEnumeration(element)
        elif element.tag == "FunctionType" or element.tag == "Function":
            dataType = self.createFunction(element)
        elif element.tag == "Method":
            dataType = self.createMemberFunction(element)
        elif element.tag == "Namespace":
            dataType = self.recordNamespace(element)
        elif element.tag == "Unimplemented":
            if 'kind' in element.attrib:
                println("WARN: Encountered Unimplemented tag for kind {0}".format(element.attrib['kind']))
            elif 'type_class' in element.attrib:
                println("WARN: Encountered Unimplemented tag for type_class {0}".format(element.attrib['type_class']))
            println("WARN: This is a limitation in CastXML.")
            println("WARN: Returning UndefinedDataType instead.")
            dataType = Undefined.getUndefinedDataType(1)
        else:
            print "Encountered unhandled tag: {0}".format(element.tag)

        return dataType


def doLoad(input, output):
    if os.path.exists(outputGDT):
        if not askYesNo("File already exists!", "Would you like to overwrite:\n" + outputGDT):
            return
        else:
            os.remove(outputGDT)

    loader = None
    try:
        loader = GhidraCastXMLLoader(output)
        #loader.setDefaultPointerSize(8)
        loader.importXML(input)
    except Exception:
        traceback.print_exc()
    except JavaException:
        traceback.print_exc()
    finally:
        loader.close()


if __name__ == "__main__":
    inputXML = askFile("Input XML File", "Open").getAbsolutePath();
    outputGDT = askFile("Output GDT File", "Save").getAbsolutePath();
    doLoad(inputXML, outputGDT)



