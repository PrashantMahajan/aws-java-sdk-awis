//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.11 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.01.28 at 01:53:15 PM IST 
//


package net.distributary.tahseen.awis.generated;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


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
 *         &lt;element ref="{http://alexa.amazonaws.com/doc/2005-10-05/}Request" minOccurs="0"/&gt;
 *         &lt;element ref="{http://alexa.amazonaws.com/doc/2005-10-05/}Errors" minOccurs="0"/&gt;
 *         &lt;element ref="{http://alexa.amazonaws.com/doc/2005-10-05/}Alexa" minOccurs="0"/&gt;
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
    "request",
    "errors",
    "alexa"
})
@XmlRootElement(name = "CrawlResult")
public class CrawlResult {

    @XmlElement(name = "Request")
    protected Request request;
    @XmlElement(name = "Errors")
    protected Errors errors;
    @XmlElement(name = "Alexa")
    protected Alexa alexa;

    /**
     * Gets the value of the request property.
     * 
     * @return
     *     possible object is
     *     {@link Request }
     *     
     */
    public Request getRequest() {
        return request;
    }

    /**
     * Sets the value of the request property.
     * 
     * @param value
     *     allowed object is
     *     {@link Request }
     *     
     */
    public void setRequest(Request value) {
        this.request = value;
    }

    /**
     * Gets the value of the errors property.
     * 
     * @return
     *     possible object is
     *     {@link Errors }
     *     
     */
    public Errors getErrors() {
        return errors;
    }

    /**
     * Sets the value of the errors property.
     * 
     * @param value
     *     allowed object is
     *     {@link Errors }
     *     
     */
    public void setErrors(Errors value) {
        this.errors = value;
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

}
