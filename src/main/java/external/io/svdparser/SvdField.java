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
 * This class represents a field within a register.
 */
public class SvdField {
	private String mName;
	private String mDescription;
	private int mBitOffset;
	private int mBitWidth;

	/**
	 * Create SvdField objects from a DOM element.
	 * 
	 * @param el DOM element object.
	 * @return A list of SvdField objects.
	 * @throws SvdParserException on SVD format errors.
	 */
	public static List<SvdField> fromElement(Element el) throws SvdParserException {
		List<SvdField> fields = new ArrayList<>();
		
		// Element null check
		if (el == null)
			return fields;

		// XML node name check
		if (!el.getNodeName().equals("field"))
			throw new SvdParserException("Cannot build an SvdField from a " + el.getNodeName() + " node!");

		// Get field name
		Element nameElement = Utils.getSingleFirstOrderChildElementByTagName(el, "name");
		String name = (nameElement != null) ? nameElement.getTextContent() : "UNKNOWN";

		// Get field description (optional)
		Element descriptionElement = Utils.getSingleFirstOrderChildElementByTagName(el, "description");
		String description = (descriptionElement != null) ? descriptionElement.getTextContent() : null;

		// Get bit offset
		Element bitOffsetElement = Utils.getSingleFirstOrderChildElementByTagName(el, "bitOffset");
		int bitOffset = 0;
		if (bitOffsetElement != null) {
			bitOffset = Integer.decode(bitOffsetElement.getTextContent());
		}

		// Get bit width
		Element bitWidthElement = Utils.getSingleFirstOrderChildElementByTagName(el, "bitWidth");
		int bitWidth = 1;
		if (bitWidthElement != null) {
			bitWidth = Integer.decode(bitWidthElement.getTextContent());
		}

		fields.add(new SvdField(name, description, bitOffset, bitWidth));
		return fields;
	}

	private SvdField(String name, String description, int bitOffset, int bitWidth) {
		mName = name;
		mDescription = description;
		mBitOffset = bitOffset;
		mBitWidth = bitWidth;
	}

	/**
	 * Get the field name.
	 * 
	 * @return A string representing the field name.
	 */
	public String getName() {
		return mName;
	}

	/**
	 * Get the field description.
	 * 
	 * @return A string representing the field description, or null if not available.
	 */
	public String getDescription() {
		return mDescription;
	}

	/**
	 * Get the bit offset.
	 * 
	 * @return The bit offset of this field.
	 */
	public int getBitOffset() {
		return mBitOffset;
	}

	/**
	 * Get the bit width.
	 * 
	 * @return The bit width of this field.
	 */
	public int getBitWidth() {
		return mBitWidth;
	}

	/**
	 * Extract the field value from a register value.
	 * 
	 * @param registerValue The full register value
	 * @return The field value extracted from the register
	 */
	public long extractValue(long registerValue) {
		// Create a mask for the field bits
		long mask = ((1L << mBitWidth) - 1) << mBitOffset;
		// Extract and shift the field value
		return (registerValue & mask) >> mBitOffset;
	}

	/**
	 * Check if this field is set (non-zero) in the given register value.
	 * 
	 * @param registerValue The full register value
	 * @return True if the field is set (non-zero)
	 */
	public boolean isSet(long registerValue) {
		return extractValue(registerValue) != 0;
	}

	public String toString() {
		return "SvdField{name=" + mName + ", bitOffset=" + mBitOffset + ", bitWidth=" + mBitWidth + "}";
	}
}