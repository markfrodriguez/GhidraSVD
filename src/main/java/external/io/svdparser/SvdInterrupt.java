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
 * This class represents an interrupt associated with a peripheral.
 */
public class SvdInterrupt {
	private String mName;
	private String mDescription;
	private int mValue;

	/**
	 * Create SvdInterrupt objects from a DOM element.
	 * 
	 * @param el DOM element object.
	 * @return A list of SvdInterrupt objects.
	 * @throws SvdParserException on SVD format errors.
	 */
	public static List<SvdInterrupt> fromElement(Element el) throws SvdParserException {
		List<SvdInterrupt> interrupts = new ArrayList<>();
		
		// Element null check
		if (el == null)
			return interrupts;

		// XML node name check
		if (!el.getNodeName().equals("interrupt"))
			throw new SvdParserException("Cannot build an SvdInterrupt from a " + el.getNodeName() + " node!");

		// Get interrupt name
		Element nameElement = Utils.getSingleFirstOrderChildElementByTagName(el, "name");
		String name = (nameElement != null) ? nameElement.getTextContent() : "UNKNOWN_IRQ";

		// Get interrupt description (optional)
		Element descriptionElement = Utils.getSingleFirstOrderChildElementByTagName(el, "description");
		String description = (descriptionElement != null) ? descriptionElement.getTextContent() : null;

		// Get interrupt value (vector number)
		Element valueElement = Utils.getSingleFirstOrderChildElementByTagName(el, "value");
		int value = 0;
		if (valueElement != null) {
			try {
				String valueText = valueElement.getTextContent().trim();
				value = Integer.parseInt(valueText);
			} catch (NumberFormatException e) {
				throw new SvdParserException("Invalid interrupt value: " + valueElement.getTextContent());
			}
		}

		interrupts.add(new SvdInterrupt(name, description, value));
		return interrupts;
	}

	private SvdInterrupt(String name, String description, int value) {
		mName = name;
		mDescription = description;
		mValue = value;
	}

	/**
	 * Get the interrupt name.
	 * 
	 * @return A string representing the interrupt name.
	 */
	public String getName() {
		return mName;
	}

	/**
	 * Get the interrupt description.
	 * 
	 * @return A string representing the interrupt description, or null if not available.
	 */
	public String getDescription() {
		return mDescription;
	}

	/**
	 * Get the interrupt vector number.
	 * 
	 * @return The interrupt vector number.
	 */
	public int getValue() {
		return mValue;
	}

	/**
	 * Check if this interrupt corresponds to a specific bit position.
	 * This is useful for interrupt enable/disable registers where each bit controls a specific interrupt.
	 * 
	 * @param bitPosition The bit position to check (0-based)
	 * @return True if this interrupt corresponds to the given bit position
	 */
	public boolean matchesBitPosition(int bitPosition) {
		// Common patterns: 
		// EIC_INTREQ_15 corresponds to bit 15
		// DMAC_INTREQ_0 corresponds to bit 0
		String namePart = mName;
		
		// Primary strategy: Extract number from end of name (covers most cases)
		if (namePart.contains("_")) {
			String[] parts = namePart.split("_");
			if (parts.length > 0) {
				String lastPart = parts[parts.length - 1];
				try {
					int irqNumber = Integer.parseInt(lastPart);
					return irqNumber == bitPosition;
				} catch (NumberFormatException e) {
					// Not a numeric suffix, try alternative strategies
				}
			}
		}
		
		// Alternative strategy: Look for numbers anywhere in the name
		for (int i = 0; i < namePart.length(); i++) {
			if (Character.isDigit(namePart.charAt(i))) {
				// Found a digit, extract the complete number
				StringBuilder numberStr = new StringBuilder();
				for (int j = i; j < namePart.length() && Character.isDigit(namePart.charAt(j)); j++) {
					numberStr.append(namePart.charAt(j));
				}
				try {
					int irqNumber = Integer.parseInt(numberStr.toString());
					if (irqNumber == bitPosition) {
						return true;
					}
				} catch (NumberFormatException e) {
					// Continue searching
				}
			}
		}
		
		// Vector-based strategy: Use interrupt vector number for mapping
		if (mValue >= 0 && mValue < 256) { // Reasonable interrupt vector range
			// Try direct mapping first
			if (mValue == bitPosition) {
				return true;
			}
			
			// Try common ARM Cortex-M offsets
			int[] commonOffsets = {16, 32, 64};
			for (int offset : commonOffsets) {
				if (mValue - offset == bitPosition) {
					return true;
				}
			}
		}
		
		return false;
	}

	/**
	 * Get interrupt information formatted for comments
	 * 
	 * @return Formatted string with interrupt name and vector number
	 */
	public String getFormattedInfo() {
		StringBuilder info = new StringBuilder();
		info.append(mName).append(" (IRQ ").append(mValue).append(")");
		if (mDescription != null && !mDescription.trim().isEmpty()) {
			info.append(" - ").append(mDescription.trim());
		}
		return info.toString();
	}

	public String toString() {
		return "SvdInterrupt{name=" + mName + ", value=" + mValue + "}";
	}
}