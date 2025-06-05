/*
 * Copyright (C) Antonio Vázquez Blanco 2023
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.svdparser;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;

/**
 * This class represents a device peripheral.
 */
public class SvdPeripheral {
	private String mName;
	private String mDescription;
	private Long mBaseAddr;
	private List<SvdAddressBlock> mAddressBlocks;
	private List<SvdRegister> mRegisters;

	/**
	 * Create an SvdPeripheral from a DOM element.
	 * 
	 * @param el           DOM element object.
	 * @param defaultSize  Default register size to inherit.
	 * @param otherPeriphs Peripherals to search for peripheral derivation.
	 * @return A SvdPeripheral peripheral object.
	 * @throws SvdParserException on SVD format errors.
	 */
	public static ArrayList<SvdPeripheral> fromElement(Element el, int defaultSize, List<SvdPeripheral> otherPeriphs)
			throws SvdParserException {
		// Element null check
		if (el == null)
			return null;

		// XML node name check
		if (!el.getNodeName().equals("peripheral"))
			throw new SvdParserException("Cannot build an SvdPeripheral from a " + el.getNodeName() + " node!");

		// Parse dim elements
		Element dimElement = Utils.getSingleFirstOrderChildElementByTagName(el, "dim");
		Integer dim = (dimElement != null) ? Integer.decode(dimElement.getTextContent()) : 1;
		Element dimIncrementElement = Utils.getSingleFirstOrderChildElementByTagName(el, "dimIncrement");
		Integer dimIncrement = (dimIncrementElement != null) ? Integer.decode(dimIncrementElement.getTextContent()) : 0;

		// Get a name
		Element nameElement = Utils.getSingleFirstOrderChildElementByTagName(el, "name");
		String name = nameElement.getTextContent();

		// Get description (optional)
		Element descriptionElement = Utils.getSingleFirstOrderChildElementByTagName(el, "description");
		String description = (descriptionElement != null) ? descriptionElement.getTextContent() : null;

		// Check if the peripheral derives from any other...
		SvdPeripheral derivedFrom = null;
		String derivedFromName = el.getAttribute("derivedFrom");
		if (derivedFromName != null && !derivedFromName.equals("")) {
			derivedFrom = Utils.getPeripheralFromName(otherPeriphs, derivedFromName);
			if (derivedFrom == null)
				throw new SvdParserException(
						"Cannot find peripheral " + derivedFromName + " to derive " + name + " from...");
		}

		// Get the base addr
		Element baseAddrElement = Utils.getSingleFirstOrderChildElementByTagName(el, "baseAddress");
		Long baseAddr = Long.decode(baseAddrElement.getTextContent());

		// Parse address blocks
		List<SvdAddressBlock> addressBlocks = new ArrayList<>();
		for (Element e : Utils.getFirstOrderChildElementsByTagName(el, "addressBlock"))
			addressBlocks.add(SvdAddressBlock.fromElement(e));

		// Try to parse a size element
		Element sizeElement = Utils.getSingleFirstOrderChildElementByTagName(el, "size");
		if (sizeElement != null)
			defaultSize = Integer.decode(sizeElement.getTextContent());

		// Parse registers (both direct registers and registers within clusters)
		List<SvdRegister> registers = new ArrayList<>();
		Element registersElement = Utils.getSingleFirstOrderChildElementByTagName(el, "registers");
		if (registersElement != null) {
			// Parse direct registers
			for (Element e : Utils.getFirstOrderChildElementsByTagName(registersElement, "register"))
				registers.addAll(SvdRegister.fromElement(e, defaultSize));
			
			// Parse registers within clusters
			for (Element clusterElement : Utils.getFirstOrderChildElementsByTagName(registersElement, "cluster")) {
				List<SvdRegister> clusterRegisters = parseClusterRegisters(clusterElement, defaultSize);
				registers.addAll(clusterRegisters);
			}
		}

		ArrayList<SvdPeripheral> periph = new ArrayList<SvdPeripheral>();
		for (Integer i = 0; i < dim; i++) {
			Integer addrIncrement = i * dimIncrement;
			String periphName = name.formatted(String.valueOf(i));
			periph.add(new SvdPeripheral(derivedFrom, periphName, description, baseAddr + addrIncrement, addressBlocks, registers));
		}
		return periph;
	}

	private SvdPeripheral(String name, String description, Long baseAddr, List<SvdAddressBlock> addressBlocks,
			List<SvdRegister> registers) {
		this(null, name, description, baseAddr, addressBlocks, registers);
	}

	private SvdPeripheral(SvdPeripheral derivedFrom, String name, String description, Long baseAddr, List<SvdAddressBlock> addressBlocks,
			List<SvdRegister> registers) {
		mName = name;
		mDescription = description;
		mBaseAddr = baseAddr;
		mAddressBlocks = new ArrayList<SvdAddressBlock>();
		mRegisters = new ArrayList<SvdRegister>();
		if (derivedFrom != null) {
			mAddressBlocks.addAll(derivedFrom.getAddressBlocks());
			mRegisters.addAll(derivedFrom.getRegisters());
			// Inherit description from derived peripheral if current one is null
			if (mDescription == null && derivedFrom.getDescription() != null) {
				mDescription = derivedFrom.getDescription();
			}
		}
		mAddressBlocks.addAll(addressBlocks);
		mRegisters.addAll(registers);
	}

	/**
	 * Get the peripheral name.
	 * 
	 * @return A string representing a peripheral name.
	 */
	public String getName() {
		return mName;
	}

	/**
	 * Get the peripheral description.
	 * 
	 * @return A string representing a peripheral description, or null if not available.
	 */
	public String getDescription() {
		return mDescription;
	}

	/**
	 * Get the peripheral base address.
	 * 
	 * @return The base address of the peripheral.
	 */
	public Long getBaseAddr() {
		return mBaseAddr;
	}

	/**
	 * Get a list of address blocks that the peripheral contains.
	 * 
	 * @return A list of SvdAddressBlock objects.
	 */
	public List<SvdAddressBlock> getAddressBlocks() {
		return mAddressBlocks;
	}

	/**
	 * Get a list of registers that the peripheral contains.
	 * 
	 * @return A list of SvdRegister objects.
	 */
	public List<SvdRegister> getRegisters() {
		return mRegisters;
	}

	/**
	 * Parse registers from a cluster element
	 * @param clusterElement The cluster DOM element
	 * @param defaultSize Default register size
	 * @return List of registers with cluster name prefixed
	 */
	private static List<SvdRegister> parseClusterRegisters(Element clusterElement, int defaultSize) 
			throws SvdParserException {
		List<SvdRegister> clusterRegisters = new ArrayList<>();
		
		// Get cluster name for prefixing register names
		Element clusterNameElement = Utils.getSingleFirstOrderChildElementByTagName(clusterElement, "name");
		String clusterName = (clusterNameElement != null) ? clusterNameElement.getTextContent() : "CLUSTER";
		
		// Get cluster description for context
		Element clusterDescElement = Utils.getSingleFirstOrderChildElementByTagName(clusterElement, "description");
		String clusterDescription = (clusterDescElement != null) ? clusterDescElement.getTextContent() : null;
		
		// Get cluster address offset (relative to peripheral base)
		Element addressOffsetElement = Utils.getSingleFirstOrderChildElementByTagName(clusterElement, "addressOffset");
		long clusterOffset = 0;
		if (addressOffsetElement != null) {
			clusterOffset = Long.decode(addressOffsetElement.getTextContent());
		}
		
		// Parse all registers within this cluster
		for (Element registerElement : Utils.getFirstOrderChildElementsByTagName(clusterElement, "register")) {
			List<SvdRegister> registers = SvdRegister.fromElement(registerElement, defaultSize);
			
			// Prefix register names with cluster name and adjust offsets
			for (SvdRegister register : registers) {
				// Create a new register with cluster-prefixed name and adjusted offset
				SvdRegister clusterRegister = createClusterRegister(register, clusterName, clusterDescription, clusterOffset);
				clusterRegisters.add(clusterRegister);
			}
		}
		
		return clusterRegisters;
	}
	
	/**
	 * Create a new register with cluster context
	 */
	private static SvdRegister createClusterRegister(SvdRegister originalRegister, String clusterName, 
			String clusterDescription, long clusterOffset) {
		// Create enhanced name: ClusterName_RegisterName (e.g., "I2CS_CTRLA", "USART_BAUD")
		String enhancedName = clusterName + "_" + originalRegister.getName();
		
		// Create enhanced description that includes cluster context
		String enhancedDescription = originalRegister.getDescription();
		if (clusterDescription != null && !clusterDescription.trim().isEmpty()) {
			if (enhancedDescription != null && !enhancedDescription.trim().isEmpty()) {
				enhancedDescription = clusterDescription + " - " + enhancedDescription;
			} else {
				enhancedDescription = clusterDescription;
			}
		}
		
		// Adjust offset to include cluster offset
		long adjustedOffset = originalRegister.getOffset() + clusterOffset;
		
		// Create new register with cluster context using the factory method
		return SvdRegister.createRegister(enhancedName, enhancedDescription, adjustedOffset, originalRegister.getSize());
	}

	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("SvdPeripheral{");
		sb.append("name=" + mName);
		sb.append(", baseAddr=0x" + Long.toHexString(mBaseAddr));
		sb.append(", regs=[");
		for (SvdRegister r : mRegisters)
			sb.append(r.toString() + ",");
		sb.append("]");
		sb.append("}");
		return sb.toString();
	}
}
