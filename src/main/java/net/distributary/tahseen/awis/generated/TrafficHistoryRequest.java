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
 * <p>Java class for TrafficHistoryRequest complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TrafficHistoryRequest"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Security" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="AWSAccessKeyId" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *                   &lt;element name="Signature" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *                   &lt;element name="Timestamp" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="Url" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="ResponseGroup" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="Version" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="Range" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="Start" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrafficHistoryRequest", propOrder = {
    "security",
    "url",
    "responseGroup",
    "version",
    "range",
    "start"
})
public class TrafficHistoryRequest {

    @XmlElement(name = "Security")
    protected TrafficHistoryRequest.Security security;
    @XmlElement(name = "Url", required = true)
    protected String url;
    @XmlElement(name = "ResponseGroup", required = true)
    protected String responseGroup;
    @XmlElement(name = "Version")
    protected String version;
    @XmlElement(name = "Range")
    protected String range;
    @XmlElement(name = "Start")
    protected String start;

    /**
     * Gets the value of the security property.
     * 
     * @return
     *     possible object is
     *     {@link TrafficHistoryRequest.Security }
     *     
     */
    public TrafficHistoryRequest.Security getSecurity() {
        return security;
    }

    /**
     * Sets the value of the security property.
     * 
     * @param value
     *     allowed object is
     *     {@link TrafficHistoryRequest.Security }
     *     
     */
    public void setSecurity(TrafficHistoryRequest.Security value) {
        this.security = value;
    }

    /**
     * Gets the value of the url property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUrl() {
        return url;
    }

    /**
     * Sets the value of the url property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUrl(String value) {
        this.url = value;
    }

    /**
     * Gets the value of the responseGroup property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getResponseGroup() {
        return responseGroup;
    }

    /**
     * Sets the value of the responseGroup property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setResponseGroup(String value) {
        this.responseGroup = value;
    }

    /**
     * Gets the value of the version property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getVersion() {
        return version;
    }

    /**
     * Sets the value of the version property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setVersion(String value) {
        this.version = value;
    }

    /**
     * Gets the value of the range property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRange() {
        return range;
    }

    /**
     * Sets the value of the range property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRange(String value) {
        this.range = value;
    }

    /**
     * Gets the value of the start property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getStart() {
        return start;
    }

    /**
     * Sets the value of the start property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setStart(String value) {
        this.start = value;
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
     *         &lt;element name="AWSAccessKeyId" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
     *         &lt;element name="Signature" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
     *         &lt;element name="Timestamp" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
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
        "awsAccessKeyId",
        "signature",
        "timestamp"
    })
    public static class Security {

        @XmlElement(name = "AWSAccessKeyId")
        protected String awsAccessKeyId;
        @XmlElement(name = "Signature")
        protected String signature;
        @XmlElement(name = "Timestamp")
        protected String timestamp;

        /**
         * Gets the value of the awsAccessKeyId property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getAWSAccessKeyId() {
            return awsAccessKeyId;
        }

        /**
         * Sets the value of the awsAccessKeyId property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setAWSAccessKeyId(String value) {
            this.awsAccessKeyId = value;
        }

        /**
         * Gets the value of the signature property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getSignature() {
            return signature;
        }

        /**
         * Sets the value of the signature property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setSignature(String value) {
            this.signature = value;
        }

        /**
         * Gets the value of the timestamp property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getTimestamp() {
            return timestamp;
        }

        /**
         * Sets the value of the timestamp property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setTimestamp(String value) {
            this.timestamp = value;
        }

    }

}
