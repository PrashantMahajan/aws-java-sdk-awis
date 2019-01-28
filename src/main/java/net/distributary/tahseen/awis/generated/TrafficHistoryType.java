//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.11 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.01.28 at 04:05:52 PM IST 
//


package net.distributary.tahseen.awis.generated;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for TrafficHistoryType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TrafficHistoryType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Range" type="{http://www.w3.org/2001/XMLSchema}integer"/&gt;
 *         &lt;element name="Site" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="Start" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="HistoricalData"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="Data" maxOccurs="unbounded" minOccurs="0"&gt;
 *                     &lt;complexType&gt;
 *                       &lt;complexContent&gt;
 *                         &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                           &lt;sequence&gt;
 *                             &lt;element name="Date" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *                             &lt;element name="PageViews"&gt;
 *                               &lt;complexType&gt;
 *                                 &lt;complexContent&gt;
 *                                   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                                     &lt;sequence&gt;
 *                                       &lt;element name="PerMillion" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *                                       &lt;element name="PerUser" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *                                     &lt;/sequence&gt;
 *                                   &lt;/restriction&gt;
 *                                 &lt;/complexContent&gt;
 *                               &lt;/complexType&gt;
 *                             &lt;/element&gt;
 *                             &lt;element name="Rank" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *                             &lt;element name="Reach"&gt;
 *                               &lt;complexType&gt;
 *                                 &lt;complexContent&gt;
 *                                   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                                     &lt;sequence&gt;
 *                                       &lt;element name="PerMillion" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *                                     &lt;/sequence&gt;
 *                                   &lt;/restriction&gt;
 *                                 &lt;/complexContent&gt;
 *                               &lt;/complexType&gt;
 *                             &lt;/element&gt;
 *                           &lt;/sequence&gt;
 *                         &lt;/restriction&gt;
 *                       &lt;/complexContent&gt;
 *                     &lt;/complexType&gt;
 *                   &lt;/element&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrafficHistoryType", propOrder = {
    "range",
    "site",
    "start",
    "historicalData"
})
public class TrafficHistoryType {

    @XmlElement(name = "Range", required = true)
    protected BigInteger range;
    @XmlElement(name = "Site", required = true)
    protected String site;
    @XmlElement(name = "Start", required = true)
    protected String start;
    @XmlElement(name = "HistoricalData", required = true)
    protected TrafficHistoryType.HistoricalData historicalData;

    /**
     * Gets the value of the range property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getRange() {
        return range;
    }

    /**
     * Sets the value of the range property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setRange(BigInteger value) {
        this.range = value;
    }

    /**
     * Gets the value of the site property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSite() {
        return site;
    }

    /**
     * Sets the value of the site property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSite(String value) {
        this.site = value;
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
     * Gets the value of the historicalData property.
     * 
     * @return
     *     possible object is
     *     {@link TrafficHistoryType.HistoricalData }
     *     
     */
    public TrafficHistoryType.HistoricalData getHistoricalData() {
        return historicalData;
    }

    /**
     * Sets the value of the historicalData property.
     * 
     * @param value
     *     allowed object is
     *     {@link TrafficHistoryType.HistoricalData }
     *     
     */
    public void setHistoricalData(TrafficHistoryType.HistoricalData value) {
        this.historicalData = value;
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
     *         &lt;element name="Data" maxOccurs="unbounded" minOccurs="0"&gt;
     *           &lt;complexType&gt;
     *             &lt;complexContent&gt;
     *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *                 &lt;sequence&gt;
     *                   &lt;element name="Date" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
     *                   &lt;element name="PageViews"&gt;
     *                     &lt;complexType&gt;
     *                       &lt;complexContent&gt;
     *                         &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *                           &lt;sequence&gt;
     *                             &lt;element name="PerMillion" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
     *                             &lt;element name="PerUser" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
     *                           &lt;/sequence&gt;
     *                         &lt;/restriction&gt;
     *                       &lt;/complexContent&gt;
     *                     &lt;/complexType&gt;
     *                   &lt;/element&gt;
     *                   &lt;element name="Rank" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
     *                   &lt;element name="Reach"&gt;
     *                     &lt;complexType&gt;
     *                       &lt;complexContent&gt;
     *                         &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *                           &lt;sequence&gt;
     *                             &lt;element name="PerMillion" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
     *                           &lt;/sequence&gt;
     *                         &lt;/restriction&gt;
     *                       &lt;/complexContent&gt;
     *                     &lt;/complexType&gt;
     *                   &lt;/element&gt;
     *                 &lt;/sequence&gt;
     *               &lt;/restriction&gt;
     *             &lt;/complexContent&gt;
     *           &lt;/complexType&gt;
     *         &lt;/element&gt;
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
        "data"
    })
    public static class HistoricalData {

        @XmlElement(name = "Data")
        protected List<TrafficHistoryType.HistoricalData.Data> data;

        /**
         * Gets the value of the data property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the data property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getData().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link TrafficHistoryType.HistoricalData.Data }
         * 
         * 
         */
        public List<TrafficHistoryType.HistoricalData.Data> getData() {
            if (data == null) {
                data = new ArrayList<TrafficHistoryType.HistoricalData.Data>();
            }
            return this.data;
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
         *         &lt;element name="Date" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
         *         &lt;element name="PageViews"&gt;
         *           &lt;complexType&gt;
         *             &lt;complexContent&gt;
         *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
         *                 &lt;sequence&gt;
         *                   &lt;element name="PerMillion" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
         *                   &lt;element name="PerUser" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
         *                 &lt;/sequence&gt;
         *               &lt;/restriction&gt;
         *             &lt;/complexContent&gt;
         *           &lt;/complexType&gt;
         *         &lt;/element&gt;
         *         &lt;element name="Rank" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
         *         &lt;element name="Reach"&gt;
         *           &lt;complexType&gt;
         *             &lt;complexContent&gt;
         *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
         *                 &lt;sequence&gt;
         *                   &lt;element name="PerMillion" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
         *                 &lt;/sequence&gt;
         *               &lt;/restriction&gt;
         *             &lt;/complexContent&gt;
         *           &lt;/complexType&gt;
         *         &lt;/element&gt;
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
            "date",
            "pageViews",
            "rank",
            "reach"
        })
        public static class Data {

            @XmlElement(name = "Date", required = true)
            protected String date;
            @XmlElement(name = "PageViews", required = true)
            protected TrafficHistoryType.HistoricalData.Data.PageViews pageViews;
            @XmlElement(name = "Rank", required = true)
            protected String rank;
            @XmlElement(name = "Reach", required = true)
            protected TrafficHistoryType.HistoricalData.Data.Reach reach;

            /**
             * Gets the value of the date property.
             * 
             * @return
             *     possible object is
             *     {@link String }
             *     
             */
            public String getDate() {
                return date;
            }

            /**
             * Sets the value of the date property.
             * 
             * @param value
             *     allowed object is
             *     {@link String }
             *     
             */
            public void setDate(String value) {
                this.date = value;
            }

            /**
             * Gets the value of the pageViews property.
             * 
             * @return
             *     possible object is
             *     {@link TrafficHistoryType.HistoricalData.Data.PageViews }
             *     
             */
            public TrafficHistoryType.HistoricalData.Data.PageViews getPageViews() {
                return pageViews;
            }

            /**
             * Sets the value of the pageViews property.
             * 
             * @param value
             *     allowed object is
             *     {@link TrafficHistoryType.HistoricalData.Data.PageViews }
             *     
             */
            public void setPageViews(TrafficHistoryType.HistoricalData.Data.PageViews value) {
                this.pageViews = value;
            }

            /**
             * Gets the value of the rank property.
             * 
             * @return
             *     possible object is
             *     {@link String }
             *     
             */
            public String getRank() {
                return rank;
            }

            /**
             * Sets the value of the rank property.
             * 
             * @param value
             *     allowed object is
             *     {@link String }
             *     
             */
            public void setRank(String value) {
                this.rank = value;
            }

            /**
             * Gets the value of the reach property.
             * 
             * @return
             *     possible object is
             *     {@link TrafficHistoryType.HistoricalData.Data.Reach }
             *     
             */
            public TrafficHistoryType.HistoricalData.Data.Reach getReach() {
                return reach;
            }

            /**
             * Sets the value of the reach property.
             * 
             * @param value
             *     allowed object is
             *     {@link TrafficHistoryType.HistoricalData.Data.Reach }
             *     
             */
            public void setReach(TrafficHistoryType.HistoricalData.Data.Reach value) {
                this.reach = value;
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
             *         &lt;element name="PerMillion" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
             *         &lt;element name="PerUser" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
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
                "perMillion",
                "perUser"
            })
            public static class PageViews {

                @XmlElement(name = "PerMillion", required = true)
                protected String perMillion;
                @XmlElement(name = "PerUser", required = true)
                protected String perUser;

                /**
                 * Gets the value of the perMillion property.
                 * 
                 * @return
                 *     possible object is
                 *     {@link String }
                 *     
                 */
                public String getPerMillion() {
                    return perMillion;
                }

                /**
                 * Sets the value of the perMillion property.
                 * 
                 * @param value
                 *     allowed object is
                 *     {@link String }
                 *     
                 */
                public void setPerMillion(String value) {
                    this.perMillion = value;
                }

                /**
                 * Gets the value of the perUser property.
                 * 
                 * @return
                 *     possible object is
                 *     {@link String }
                 *     
                 */
                public String getPerUser() {
                    return perUser;
                }

                /**
                 * Sets the value of the perUser property.
                 * 
                 * @param value
                 *     allowed object is
                 *     {@link String }
                 *     
                 */
                public void setPerUser(String value) {
                    this.perUser = value;
                }

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
             *         &lt;element name="PerMillion" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
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
                "perMillion"
            })
            public static class Reach {

                @XmlElement(name = "PerMillion", required = true)
                protected String perMillion;

                /**
                 * Gets the value of the perMillion property.
                 * 
                 * @return
                 *     possible object is
                 *     {@link String }
                 *     
                 */
                public String getPerMillion() {
                    return perMillion;
                }

                /**
                 * Sets the value of the perMillion property.
                 * 
                 * @param value
                 *     allowed object is
                 *     {@link String }
                 *     
                 */
                public void setPerMillion(String value) {
                    this.perMillion = value;
                }

            }

        }

    }

}
