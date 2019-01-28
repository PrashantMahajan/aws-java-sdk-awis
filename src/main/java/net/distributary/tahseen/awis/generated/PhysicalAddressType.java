//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.11 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.01.28 at 04:05:52 PM IST 
//


package net.distributary.tahseen.awis.generated;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * Defines a structure for a physical (e.g. mailing) address
 * 
 * <p>Java class for PhysicalAddressType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PhysicalAddressType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Streets" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="Street" type="{http://awis.amazonaws.com/doc/2005-10-05}GenericDataType" maxOccurs="unbounded"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="City" type="{http://awis.amazonaws.com/doc/2005-10-05}GenericDataType" minOccurs="0"/&gt;
 *         &lt;element name="State" type="{http://awis.amazonaws.com/doc/2005-10-05}GenericDataType" minOccurs="0"/&gt;
 *         &lt;element name="PostalCode" type="{http://awis.amazonaws.com/doc/2005-10-05}GenericDataType" minOccurs="0"/&gt;
 *         &lt;element name="Country" type="{http://awis.amazonaws.com/doc/2005-10-05}GenericDataType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PhysicalAddressType", propOrder = {
    "streets",
    "city",
    "state",
    "postalCode",
    "country"
})
@XmlSeeAlso({
    net.distributary.tahseen.awis.generated.ContactInfoType.PhysicalAddress.class
})
public class PhysicalAddressType {

    @XmlElement(name = "Streets")
    protected PhysicalAddressType.Streets streets;
    @XmlElement(name = "City")
    protected GenericDataType city;
    @XmlElement(name = "State")
    protected GenericDataType state;
    @XmlElement(name = "PostalCode")
    protected GenericDataType postalCode;
    @XmlElement(name = "Country")
    protected GenericDataType country;

    /**
     * Gets the value of the streets property.
     * 
     * @return
     *     possible object is
     *     {@link PhysicalAddressType.Streets }
     *     
     */
    public PhysicalAddressType.Streets getStreets() {
        return streets;
    }

    /**
     * Sets the value of the streets property.
     * 
     * @param value
     *     allowed object is
     *     {@link PhysicalAddressType.Streets }
     *     
     */
    public void setStreets(PhysicalAddressType.Streets value) {
        this.streets = value;
    }

    /**
     * Gets the value of the city property.
     * 
     * @return
     *     possible object is
     *     {@link GenericDataType }
     *     
     */
    public GenericDataType getCity() {
        return city;
    }

    /**
     * Sets the value of the city property.
     * 
     * @param value
     *     allowed object is
     *     {@link GenericDataType }
     *     
     */
    public void setCity(GenericDataType value) {
        this.city = value;
    }

    /**
     * Gets the value of the state property.
     * 
     * @return
     *     possible object is
     *     {@link GenericDataType }
     *     
     */
    public GenericDataType getState() {
        return state;
    }

    /**
     * Sets the value of the state property.
     * 
     * @param value
     *     allowed object is
     *     {@link GenericDataType }
     *     
     */
    public void setState(GenericDataType value) {
        this.state = value;
    }

    /**
     * Gets the value of the postalCode property.
     * 
     * @return
     *     possible object is
     *     {@link GenericDataType }
     *     
     */
    public GenericDataType getPostalCode() {
        return postalCode;
    }

    /**
     * Sets the value of the postalCode property.
     * 
     * @param value
     *     allowed object is
     *     {@link GenericDataType }
     *     
     */
    public void setPostalCode(GenericDataType value) {
        this.postalCode = value;
    }

    /**
     * Gets the value of the country property.
     * 
     * @return
     *     possible object is
     *     {@link GenericDataType }
     *     
     */
    public GenericDataType getCountry() {
        return country;
    }

    /**
     * Sets the value of the country property.
     * 
     * @param value
     *     allowed object is
     *     {@link GenericDataType }
     *     
     */
    public void setCountry(GenericDataType value) {
        this.country = value;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType&gt;
     *   &lt;complexContent&gt;
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *       &lt;sequence&gt;
     *         &lt;element name="Street" type="{http://awis.amazonaws.com/doc/2005-10-05}GenericDataType" maxOccurs="unbounded"/&gt;
     *       &lt;/sequence&gt;
     *     &lt;/restriction&gt;
     *   &lt;/complexContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "street"
    })
    public static class Streets {

        @XmlElement(name = "Street", required = true)
        protected List<GenericDataType> street;

        /**
         * Gets the value of the street property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the street property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getStreet().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link GenericDataType }
         * 
         * 
         */
        public List<GenericDataType> getStreet() {
            if (street == null) {
                street = new ArrayList<GenericDataType>();
            }
            return this.street;
        }

    }

}
