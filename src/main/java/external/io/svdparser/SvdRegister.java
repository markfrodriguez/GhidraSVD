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
 * This class represents a register of a device peripheral.
 */
public class SvdRegister {

	private String mName;
	private String mDescription;
	private Integer mSize;
	private Integer mOffset;
	private List<SvdField> mFields;

	/**
	 * Create an SvdRegister from a DOM element.
	 * 
	 * @param el          DOM element object.
	 * @param defaultSize Default register size to inherit.
	 * @return A SvdRegister object.
	 * @throws SvdParserException on SVD format errors.
	 */
	public static ArrayList<SvdRegister> fromElement(Element el, Integer defaultSize) throws SvdParserException {
		// Element null check
		if (el == null)
			return null;

		// XML node name check
		if (!el.getNodeName().equals("register"))
			throw new SvdParserException("Cannot build an SvdRegister from a " + el.getNodeName() + " node!");

		// Parse dim elements
		Element dimElement = Utils.getSingleFirstOrderChildElementByTagName(el, "dim");
		Integer dim = (dimElement != null) ? Integer.decode(dimElement.getTextContent()) : 1;
		Element dimIncrementElement = Utils.getSingleFirstOrderChildElementByTagName(el, "dimIncrement");
		Integer dimIncrement = (dimIncrementElement != null) ? Integer.decode(dimIncrementElement.getTextContent()) : 0;

		// Get a name
		Element nameElement = Utils.getSingleFirstOrderChildElementByTagName(el, "name");
		String name = nameElement.getTextContent();

		// Get a description
		Element descriptionElement = Utils.getSingleFirstOrderChildElementByTagName(el, "description");
		String description = (descriptionElement != null) ? descriptionElement.getTextContent() : null;

		// Get the size
		Element sizeElement = Utils.getSingleFirstOrderChildElementByTagName(el, "size");
		if (sizeElement != null)
			defaultSize = Integer.decode(sizeElement.getTextContent());

		// Get the offset
		Element offsetElement = Utils.getSingleFirstOrderChildElementByTagName(el, "addressOffset");
		Integer offset = Integer.decode(offsetElement.getTextContent());

		// Parse fields (optional)
		List<SvdField> fields = new ArrayList<>();
		Element fieldsElement = Utils.getSingleFirstOrderChildElementByTagName(el, "fields");
		if (fieldsElement != null) {
			for (Element fieldElement : Utils.getFirstOrderChildElementsByTagName(fieldsElement, "field")) {
				fields.addAll(SvdField.fromElement(fieldElement));
			}
		}

		ArrayList<SvdRegister> regs = new ArrayList<SvdRegister>();
		for (Integer i = 0; i < dim; i++) {
			Integer addrIncrement = i * dimIncrement;
			String regName = name.formatted(String.valueOf(i));
			regs.add(new SvdRegister(regName, description, defaultSize, offset + addrIncrement, fields));
		}
		return regs;
	}

	private SvdRegister(String name, String description, int size, int offset) {
		this(name, description, size, offset, new ArrayList<>());
	}

	private SvdRegister(String name, String description, int size, int offset, List<SvdField> fields) {
		mName = name;
		mDescription = description;
		mSize = size;
		mOffset = offset;
		mFields = new ArrayList<>(fields); // Create a copy to avoid sharing references
	}
	
	/**
	 * Create an SvdRegister with specific parameters (for cluster support)
	 * 
	 * @param name        Register name
	 * @param description Register description
	 * @param offset      Register offset
	 * @param size        Register size
	 * @return A new SvdRegister object
	 */
	public static SvdRegister createRegister(String name, String description, long offset, int size) {
		return new SvdRegister(name, description, size, (int) offset, new ArrayList<>());
	}

	/**
	 * Create an SvdRegister with specific parameters including fields (for cluster support)
	 * 
	 * @param name        Register name
	 * @param description Register description
	 * @param offset      Register offset
	 * @param size        Register size
	 * @param fields      Register fields
	 * @return A new SvdRegister object
	 */
	public static SvdRegister createRegister(String name, String description, long offset, int size, List<SvdField> fields) {
		return new SvdRegister(name, description, size, (int) offset, fields);
	}

	/**
	 * Get the register name.
	 * 
	 * @return A string representing a register name.
	 */
	public String getName() {
		return mName;
	}

	/**
	 * Get the register description.
	 * 
	 * @return A string containing the register description.
	 */
	public String getDescription() {
		return mDescription;
	}

	/**
	 * Get the register size.
	 * 
	 * @return The size of the register.
	 */
	public Integer getSize() {
		return mSize;
	}

	/**
	 * Get the register fields.
	 * 
	 * @return A list of SvdField objects representing the register's fields.
	 */
	public List<SvdField> getFields() {
		return mFields;
	}

	/**
	 * Get the register offset.
	 * 
	 * @return The offset of the register.
	 */
	public Integer getOffset() {
		return mOffset;
	}

	public String toString() {
		return "SvdRegister{name=" + mName + "}";
	}
}
