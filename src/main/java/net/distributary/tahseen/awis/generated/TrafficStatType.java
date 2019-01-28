//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.11 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.01.28 at 02:03:00 PM IST 
//


package net.distributary.tahseen.awis.generated;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * Structure defining a single Traffic Statistic (value and delta)
 * 
 * <p>Java class for TrafficStatType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TrafficStatType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Value" type="{http://alexa.amazonaws.com/doc/2005-10-05/}GenericDataType"/&gt;
 *         &lt;element name="Delta" type="{http://alexa.amazonaws.com/doc/2005-10-05/}GenericDataType"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrafficStatType", propOrder = {
    "value",
    "delta"
})
public class TrafficStatType {

    @XmlElement(name = "Value", required = true)
    protected GenericDataType value;
    @XmlElement(name = "Delta", required = true)
    protected GenericDataType delta;

    /**
     * Gets the value of the value property.
     * 
     * @return
     *     possible object is
     *     {@link GenericDataType }
     *     
     */
    public GenericDataType getValue() {
        return value;
    }

    /**
     * Sets the value of the value property.
     * 
     * @param value
     *     allowed object is
     *     {@link GenericDataType }
     *     
     */
    public void setValue(GenericDataType value) {
        this.value = value;
    }

    /**
     * Gets the value of the delta property.
     * 
     * @return
     *     possible object is
     *     {@link GenericDataType }
     *     
     */
    public GenericDataType getDelta() {
        return delta;
    }

    /**
     * Sets the value of the delta property.
     * 
     * @param value
     *     allowed object is
     *     {@link GenericDataType }
     *     
     */
    public void setDelta(GenericDataType value) {
        this.delta = value;
    }

}
