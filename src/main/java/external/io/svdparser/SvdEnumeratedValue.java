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
 * This class represents an enumerated value within a field.
 */
public class SvdEnumeratedValue {
	private String mName;
	private String mDescription;
	private long mValue;

	/**
	 * Create SvdEnumeratedValue objects from a DOM element.
	 * 
	 * @param el DOM element object.
	 * @return A list of SvdEnumeratedValue objects.
	 * @throws SvdParserException on SVD format errors.
	 */
	public static List<SvdEnumeratedValue> fromElement(Element el) throws SvdParserException {
		List<SvdEnumeratedValue> enumeratedValues = new ArrayList<>();
		
		// Element null check
		if (el == null)
			return enumeratedValues;

		// XML node name check
		if (!el.getNodeName().equals("enumeratedValue"))
			throw new SvdParserException("Cannot build an SvdEnumeratedValue from a " + el.getNodeName() + " node!");

		// Get enumerated value name
		Element nameElement = Utils.getSingleFirstOrderChildElementByTagName(el, "name");
		String name = (nameElement != null) ? nameElement.getTextContent() : "UNKNOWN";

		// Get enumerated value description (optional)
		Element descriptionElement = Utils.getSingleFirstOrderChildElementByTagName(el, "description");
		String description = (descriptionElement != null) ? descriptionElement.getTextContent() : null;

		// Get enumerated value
		Element valueElement = Utils.getSingleFirstOrderChildElementByTagName(el, "value");
		long value = 0;
		if (valueElement != null) {
			String valueText = valueElement.getTextContent().trim();
			try {
				// Handle hex (0x), binary (0b), or decimal values
				if (valueText.startsWith("0x") || valueText.startsWith("0X")) {
					value = Long.parseLong(valueText.substring(2), 16);
				} else if (valueText.startsWith("0b") || valueText.startsWith("0B")) {
					value = Long.parseLong(valueText.substring(2), 2);
				} else {
					value = Long.parseLong(valueText);
				}
			} catch (NumberFormatException e) {
				throw new SvdParserException("Invalid enumerated value: " + valueText);
			}
		}

		enumeratedValues.add(new SvdEnumeratedValue(name, description, value));
		return enumeratedValues;
	}

	private SvdEnumeratedValue(String name, String description, long value) {
		mName = name;
		mDescription = description;
		mValue = value;
	}

	/**
	 * Get the enumerated value name.
	 * 
	 * @return A string representing the enumerated value name.
	 */
	public String getName() {
		return mName;
	}

	/**
	 * Get the enumerated value description.
	 * 
	 * @return A string representing the enumerated value description, or null if not available.
	 */
	public String getDescription() {
		return mDescription;
	}

	/**
	 * Get the enumerated value.
	 * 
	 * @return The numeric value of this enumerated value.
	 */
	public long getValue() {
		return mValue;
	}

	/**
	 * Check if this enumerated value matches the given field value.
	 * 
	 * @param fieldValue The field value to check against
	 * @return True if this enumerated value matches the field value
	 */
	public boolean matches(long fieldValue) {
		return mValue == fieldValue;
	}

	public String toString() {
		return "SvdEnumeratedValue{name=" + mName + ", value=0x" + Long.toHexString(mValue).toUpperCase() + "}";
	}
}