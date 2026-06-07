/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package svd.task;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import io.svdparser.SvdAddressBlock;
import io.svdparser.SvdDevice;
import io.svdparser.SvdEnumeratedValue;
import io.svdparser.SvdEnumeratedValues;
import io.svdparser.SvdField;
import io.svdparser.SvdPeripheral;
import io.svdparser.SvdRegister;

public class SvdDataTypesCreateTask extends Task {
	private Program mProgram;
	private SymbolTable mSymTable;
	private AddressSpace mAddrSpace;
	private SvdDevice mSvdDevice;
	private List<String> mWarnings;

	public SvdDataTypesCreateTask(Program program, SvdDevice svdDevice) {
		super("Create SVD Symbols and Data Types", true, false, true, true);
		mProgram = program;
		mAddrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
		mSymTable = program.getSymbolTable();
		mSvdDevice = svdDevice;
		mWarnings = new ArrayList<String>();
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		// Perform all of the work inside a single transaction so that the undo
		// history stays manageable and a successful run is committed atomically.
		int transactionId = mProgram.startTransaction("Load SVD data types");
		boolean ok = false;
		try {
			Namespace namespace = getOrCreateNamespace("Peripherals");

			for (SvdPeripheral periph : mSvdDevice.getPeripherals()) {
				monitor.checkCancelled();
				monitor.setMessage("Processing symbols and data types for " + periph.getName() + "...");
				// A problem with a single peripheral should not abort the whole import.
				try {
					processPeripheral(monitor, namespace, periph);
				} catch (CancelledException e) {
					throw e;
				} catch (Exception e) {
					mWarnings.add("Failed to process peripheral " + periph.getName() + ": " + e.getMessage());
					Msg.error(this, "Failed to process peripheral " + periph.getName(), e);
				}
			}
			ok = true;
		} finally {
			mProgram.endTransaction(transactionId, ok);
		}

		reportWarnings();
	}

	private void reportWarnings() {
		if (mWarnings.isEmpty())
			return;

		StringBuilder sb = new StringBuilder();
		sb.append("SVD data type creation finished with ").append(mWarnings.size()).append(" warning(s):\n");
		int shown = 0;
		for (String warning : mWarnings) {
			if (shown >= 20) {
				sb.append("...and ").append(mWarnings.size() - shown).append(" more (see the log).\n");
				break;
			}
			sb.append(" - ").append(warning).append('\n');
			shown++;
		}
		Msg.showWarn(this, null, "Load SVD", sb.toString());
	}

	private Namespace getOrCreateNamespace(String name) {
		Namespace namespace = mSymTable.getNamespace(name, null);
		if (namespace != null)
			return namespace;

		try {
			namespace = mSymTable.createNameSpace(null, name, SourceType.IMPORTED);
		} catch (DuplicateNameException | InvalidInputException e) {
			Msg.error(this, "Could not create namespace " + name, e);
		}
		return namespace;
	}

	private void processPeripheral(TaskMonitor monitor, Namespace namespace, SvdPeripheral periph)
			throws CancelledException {
		monitor.checkCancelled();
		createPeripheralSymbol(namespace, periph);

		// Track which registers get placed so we can flag any that fall outside of
		// every declared address block.
		List<SvdRegister> registers = periph.getRegisters();
		boolean[] placed = new boolean[registers.size()];

		for (SvdAddressBlock block : periph.getAddressBlocks()) {
			monitor.checkCancelled();
			processPeripheralAddressBlock(periph, block, placed);
		}

		for (int i = 0; i < registers.size(); i++) {
			if (!placed[i]) {
				SvdRegister reg = registers.get(i);
				mWarnings.add(periph.getName() + "." + reg.getName() + " @ +0x" + Long.toHexString(reg.getOffset())
						+ " is outside every address block; it was not typed.");
			}
		}
	}

	private void createPeripheralSymbol(Namespace namespace, SvdPeripheral periph) {
		Address addr = mAddrSpace.getAddress(periph.getBaseAddr().longValue());
		try {
			mSymTable.createLabel(addr, periph.getName(), namespace, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			mWarnings.add("Could not create symbol for " + periph.getName() + ": " + e.getMessage());
		}
	}

	private void processPeripheralAddressBlock(SvdPeripheral periph, SvdAddressBlock block, boolean[] placed) {
		int blockSize = block.getSize().intValue();
		if (blockSize <= 0) {
			mWarnings.add("Skipping zero sized address block of " + periph.getName() + ".");
			return;
		}
		StructureDataType dataType = createPeripheralBlockDataType(periph, block, placed);
		DataType resolved = commitPeripheralBlockDataType(dataType);
		if (resolved != null)
			createListingBlockData(resolved, periph, block);
	}

	private StructureDataType createPeripheralBlockDataType(SvdPeripheral periph, SvdAddressBlock block,
			boolean[] placed) {
		String structName = getPeriphBlockDataTypeName(periph, block);
		int blockSize = block.getSize().intValue();
		StructureDataType struct = new StructureDataType(structName, blockSize);

		// Registers carry peripheral relative offsets. Only place those that fall
		// inside this particular address block window and convert them to block
		// relative offsets so that multi-block peripherals are handled correctly.
		long blockStart = block.getOffset();
		long blockEnd = blockStart + block.getSize();
		List<SvdRegister> registers = periph.getRegisters();
		for (int i = 0; i < registers.size(); i++) {
			SvdRegister reg = registers.get(i);
			long offset = reg.getOffset();
			if (offset < blockStart || offset >= blockEnd)
				continue;

			int relOffset = (int) (offset - blockStart);
			int regBytes = reg.getSize() / 8;
			if (relOffset + regBytes > blockSize) {
				mWarnings.add(periph.getName() + "." + reg.getName() + " extends past block " + structName
						+ "; it was skipped.");
				continue;
			}

			try {
				// Use -1 as the length so that the resolved fixed-length datatype size is used.
				struct.replaceAtOffset(relOffset, createRegisterDataType(reg), -1, reg.getName(),
						buildRegisterComment(reg));
				placed[i] = true;
			} catch (Exception e) {
				mWarnings.add("Could not place " + periph.getName() + "." + reg.getName() + ": " + e.getMessage());
			}
		}
		return struct;
	}

	private DataType createRegisterDataType(SvdRegister reg) {
		int sizeBits = reg.getSize();
		int sizeBytes = sizeBits / 8;
		DataType baseType = getUnsignedType(sizeBytes);

		List<SvdField> fields = reg.getFields();

		// A register without fields is just an unsigned integer of the register width.
		if (fields == null || fields.isEmpty())
			return baseType;

		// Bitfields require an integer base datatype. Fall back to a 32-bit unsigned
		// integer for the (very rare) registers whose width is not a standard size.
		DataType bitfieldBase = (baseType instanceof AbstractIntegerDataType) ? baseType : new UnsignedIntegerDataType();

		StructureDataType struct = new StructureDataType(reg.getName() + "_t", sizeBytes);
		struct.setPackingEnabled(true);
		fields.sort(Comparator.comparingInt(SvdField::getBitOffset));

		int ordinal = 0;
		int nextBit = 0;
		for (SvdField field : fields) {
			int fieldOffset = field.getBitOffset();
			int fieldWidth = field.getBitWidth();

			// Skip fields that overlap an already placed field...
			if (fieldOffset < nextBit) {
				mWarnings.add(reg.getName() + "." + field.getName() + " overlaps a previous field; it was skipped.");
				continue;
			}
			// Skip fields that exceed the register width...
			if (fieldOffset + fieldWidth > sizeBits) {
				mWarnings.add(reg.getName() + "." + field.getName() + " exceeds the register width; it was skipped.");
				continue;
			}

			// Pad the gap before the field so packing reproduces the exact bit offset...
			int padding = fieldOffset - nextBit;
			if (padding > 0)
				ordinal = insertBitField(struct, ordinal, bitfieldBase, padding, "", "");

			ordinal = insertBitField(struct, ordinal, bitfieldBase, fieldWidth, field.getName(), buildFieldComment(field));
			nextBit = fieldOffset + fieldWidth;
		}

		// Pad any remaining reserved bits so the structure keeps the full register width.
		if (nextBit < sizeBits)
			insertBitField(struct, ordinal, bitfieldBase, sizeBits - nextBit, "", "");

		return struct;
	}

	private int insertBitField(StructureDataType struct, int ordinal, DataType baseType, int bitSize, String name,
			String comment) {
		// With packing enabled the byteWidth and bitOffset arguments are ignored and
		// recomputed, so packing places this bitfield right after the previous one.
		try {
			struct.insertBitField(ordinal, baseType.getLength(), 0, baseType, bitSize, name, comment);
			return ordinal + 1;
		} catch (InvalidDataTypeException | IndexOutOfBoundsException e) {
			mWarnings.add("Could not insert bitfield " + (name == null || name.isEmpty() ? "<padding>" : name) + ": "
					+ e.getMessage());
			return ordinal;
		}
	}

	private DataType getUnsignedType(int sizeBytes) {
		DataType dt = AbstractIntegerDataType.getUnsignedDataType(sizeBytes, mProgram.getDataTypeManager());
		if (dt == null)
			dt = new UnsignedIntegerDataType();
		return dt;
	}

	private String buildRegisterComment(SvdRegister reg) {
		StringBuilder sb = new StringBuilder();
		appendIfPresent(sb, reg.getDescription());
		if (reg.getAccess() != null)
			appendLine(sb, "Access: " + reg.getAccess().getSvdValue());
		return sb.length() == 0 ? null : sb.toString();
	}

	private String buildFieldComment(SvdField field) {
		StringBuilder sb = new StringBuilder();
		appendIfPresent(sb, field.getDescription());
		if (field.getAccess() != null)
			appendLine(sb, "Access: " + field.getAccess().getSvdValue());

		List<SvdEnumeratedValues> enumeratedValues = field.getEnumeratedValues();
		if (enumeratedValues != null) {
			for (SvdEnumeratedValues values : enumeratedValues) {
				List<SvdEnumeratedValue> valueList = values.getValues();
				if (valueList == null || valueList.isEmpty())
					continue;
				String header = "Values";
				if (values.getUsage() != null)
					header += " (" + values.getUsage().getSvdValue() + ")";
				appendLine(sb, header + ":");
				for (SvdEnumeratedValue value : valueList) {
					StringBuilder line = new StringBuilder("  ");
					if (value.getValue() != null)
						line.append("0x").append(Long.toHexString(value.getValue())).append(" = ");
					line.append(value.getName());
					if (value.getDescription() != null && !value.getDescription().isEmpty())
						line.append(" : ").append(value.getDescription());
					appendLine(sb, line.toString());
				}
			}
		}
		return sb.length() == 0 ? null : sb.toString();
	}

	private void appendIfPresent(StringBuilder sb, String text) {
		if (text != null && !text.isEmpty())
			appendLine(sb, text);
	}

	private void appendLine(StringBuilder sb, String text) {
		if (sb.length() > 0)
			sb.append('\n');
		sb.append(text);
	}

	private String getPeriphBlockDataTypeName(SvdPeripheral periph, SvdAddressBlock block) {
		String name = periph.getName();
		String blockUsage = block.getUsage();
		if (blockUsage != null && !blockUsage.isEmpty()) {
			name += "_" + blockUsage;
		}
		return name + "_t";
	}

	private DataType commitPeripheralBlockDataType(StructureDataType dataType) {
		// Add struct to the data type manager and return the resolved instance...
		ProgramBasedDataTypeManager dataTypeManager = mProgram.getDataTypeManager();
		try {
			return dataTypeManager.addDataType(dataType, DataTypeConflictHandler.REPLACE_HANDLER);
		} catch (IllegalArgumentException e) {
			mWarnings.add("Could not create data type " + dataType.getName() + ": " + e.getMessage());
			return null;
		}
	}

	private void createListingBlockData(DataType dataType, SvdPeripheral periph, SvdAddressBlock block) {
		// Calculate address of the block...
		Long addrValue = periph.getBaseAddr() + block.getOffset();
		Address addr = mAddrSpace.getAddress(addrValue.longValue());

		// Add data type to listing...
		Listing listing = mProgram.getListing();
		try {
			listing.createData(addr, dataType);
		} catch (CodeUnitInsertionException e) {
			mWarnings.add("Could not place " + dataType.getName() + " at " + addr + ": " + e.getMessage());
		}
	}
}
