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
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for CategoryListingsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CategoryListingsType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="RecursiveCount" type="{http://www.w3.org/2001/XMLSchema}token"/&gt;
 *         &lt;element name="Count" type="{http://www.w3.org/2001/XMLSchema}token"/&gt;
 *         &lt;element name="Listings" type="{http://alexa.amazonaws.com/doc/2005-10-05/}ListingsType" minOccurs="0"/&gt;
 *         &lt;element name="ReviewersRaveListings" type="{http://alexa.amazonaws.com/doc/2005-10-05/}ListingsType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CategoryListingsType", propOrder = {
    "recursiveCount",
    "count",
    "listings",
    "reviewersRaveListings"
})
public class CategoryListingsType {

    @XmlElement(name = "RecursiveCount", required = true)
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlSchemaType(name = "token")
    protected String recursiveCount;
    @XmlElement(name = "Count", required = true)
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlSchemaType(name = "token")
    protected String count;
    @XmlElement(name = "Listings")
    protected ListingsType listings;
    @XmlElement(name = "ReviewersRaveListings")
    protected ListingsType reviewersRaveListings;

    /**
     * Gets the value of the recursiveCount property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRecursiveCount() {
        return recursiveCount;
    }

    /**
     * Sets the value of the recursiveCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRecursiveCount(String value) {
        this.recursiveCount = value;
    }

    /**
     * Gets the value of the count property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCount() {
        return count;
    }

    /**
     * Sets the value of the count property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCount(String value) {
        this.count = value;
    }

    /**
     * Gets the value of the listings property.
     * 
     * @return
     *     possible object is
     *     {@link ListingsType }
     *     
     */
    public ListingsType getListings() {
        return listings;
    }

    /**
     * Sets the value of the listings property.
     * 
     * @param value
     *     allowed object is
     *     {@link ListingsType }
     *     
     */
    public void setListings(ListingsType value) {
        this.listings = value;
    }

    /**
     * Gets the value of the reviewersRaveListings property.
     * 
     * @return
     *     possible object is
     *     {@link ListingsType }
     *     
     */
    public ListingsType getReviewersRaveListings() {
        return reviewersRaveListings;
    }

    /**
     * Sets the value of the reviewersRaveListings property.
     * 
     * @param value
     *     allowed object is
     *     {@link ListingsType }
     *     
     */
    public void setReviewersRaveListings(ListingsType value) {
        this.reviewersRaveListings = value;
    }

}
