//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.11 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.01.28 at 04:05:52 PM IST 
//


package net.distributary.tahseen.awis.generated;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * Base type for services that take a URI as a parameter and return data about that URI.
 * 
 * <p>Java class for UrlServiceType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="UrlServiceType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="DataUrl"&gt;
 *           &lt;complexType&gt;
 *             &lt;simpleContent&gt;
 *               &lt;extension base="&lt;http://awis.amazonaws.com/doc/2005-10-05&gt;GenericDataType"&gt;
 *                 &lt;attribute name="type" type="{http://www.w3.org/2001/XMLSchema}token" /&gt;
 *               &lt;/extension&gt;
 *             &lt;/simpleContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="NavigableUrl" type="{http://awis.amazonaws.com/doc/2005-10-05}GenericDataType" minOccurs="0"/&gt;
 *         &lt;element ref="{http://awis.amazonaws.com/doc/2005-10-05}Alexa" minOccurs="0"/&gt;
 *         &lt;element name="Asin" type="{http://www.w3.org/2001/XMLSchema}token" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "UrlServiceType", propOrder = {
    "dataUrl",
    "navigableUrl",
    "alexa",
    "asin"
})
@XmlSeeAlso({
    ContactInfoType.class,
    ContentDataType.class,
    RelatedType.class,
    TrafficDataType.class,
    Alexa.WebMapData.class,
    RelatedLinkType.class,
    net.distributary.tahseen.awis.generated.WebMapSubType.Results.Result.class
})
public class UrlServiceType {

    @XmlElement(name = "DataUrl", required = true)
    protected UrlServiceType.DataUrl dataUrl;
    @XmlElement(name = "NavigableUrl")
    protected GenericDataType navigableUrl;
    @XmlElement(name = "Alexa")
    protected Alexa alexa;
    @XmlElement(name = "Asin")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlSchemaType(name = "token")
    protected String asin;

    /**
     * Gets the value of the dataUrl property.
     * 
     * @return
     *     possible object is
     *     {@link UrlServiceType.DataUrl }
     *     
     */
    public UrlServiceType.DataUrl getDataUrl() {
        return dataUrl;
    }

    /**
     * Sets the value of the dataUrl property.
     * 
     * @param value
     *     allowed object is
     *     {@link UrlServiceType.DataUrl }
     *     
     */
    public void setDataUrl(UrlServiceType.DataUrl value) {
        this.dataUrl = value;
    }

    /**
     * Gets the value of the navigableUrl property.
     * 
     * @return
     *     possible object is
     *     {@link GenericDataType }
     *     
     */
    public GenericDataType getNavigableUrl() {
        return navigableUrl;
    }

    /**
     * Sets the value of the navigableUrl property.
     * 
     * @param value
     *     allowed object is
     *     {@link GenericDataType }
     *     
     */
    public void setNavigableUrl(GenericDataType value) {
        this.navigableUrl = value;
    }

    /**
     * Gets the value of the alexa property.
     * 
     * @return
     *     possible object is
     *     {@link Alexa }
     *     
     */
    public Alexa getAlexa() {
        return alexa;
    }

    /**
     * Sets the value of the alexa property.
     * 
     * @param value
     *     allowed object is
     *     {@link Alexa }
     *     
     */
    public void setAlexa(Alexa value) {
        this.alexa = value;
    }

    /**
     * Gets the value of the asin property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAsin() {
        return asin;
    }

    /**
     * Sets the value of the asin property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAsin(String value) {
        this.asin = value;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType&gt;
     *   &lt;simpleContent&gt;
     *     &lt;extension base="&lt;http://awis.amazonaws.com/doc/2005-10-05&gt;GenericDataType"&gt;
     *       &lt;attribute name="type" type="{http://www.w3.org/2001/XMLSchema}token" /&gt;
     *     &lt;/extension&gt;
     *   &lt;/simpleContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    public static class DataUrl
        extends GenericDataType
    {

        @XmlAttribute(name = "type")
        @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
        @XmlSchemaType(name = "token")
        protected String type;

        /**
         * Gets the value of the type property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getType() {
            return type;
        }

        /**
         * Sets the value of the type property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setType(String value) {
            this.type = value;
        }

    }

}
