package net.distributary.tahseen.awis;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.xml.bind.JAXBException;

import net.distributary.tahseen.awis.AlexaWebInformationServiceClient;
import net.distributary.tahseen.awis.CategoryBrowseRequest;
import net.distributary.tahseen.awis.CategoryListingsRequest;
import net.distributary.tahseen.awis.SitesLinkingInRequest;
import net.distributary.tahseen.awis.TrafficHistoryRequest;
import net.distributary.tahseen.awis.UrlInfoRequest;
import net.distributary.tahseen.awis.enums.CategoryBrowseResponseGroup;
import net.distributary.tahseen.awis.enums.SortBy;
import net.distributary.tahseen.awis.enums.UrlInfoResponseGroup;
import net.distributary.tahseen.awis.generated.CategoryBrowseResponse;
import net.distributary.tahseen.awis.generated.CategoryListingsResponse;
import net.distributary.tahseen.awis.generated.SitesLinkingInResponse;
import net.distributary.tahseen.awis.generated.TrafficHistoryResponse;
import net.distributary.tahseen.awis.generated.UrlInfoResponse;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;


public class AlexaWebInformationServiceClientTest {
    protected final static Logger logger = LoggerFactory.getLogger(AlexaWebInformationServiceClientTest.class);

    private static AWSCredentials credentials;
    
    @BeforeClass
    public static void before() {
//        DefaultAWSCredentialsProviderChain defaultAWSCredentialsProviderChain = new DefaultAWSCredentialsProviderChain();
        credentials = new BasicAWSCredentials("AKIAJOLWZWD3OMDEVAGQ", "Cy7Vx1+rnle7pNipWNIoshfUKEObJpRI4NDkPcsw");
    }
    
    @Test
    public void testGetUrlInfo() throws SignatureException, IOException, JAXBException {
        AlexaWebInformationServiceClient client = new AlexaWebInformationServiceClient(credentials);
        
        UrlInfoRequest request = new UrlInfoRequest();
        request.setResponseGroups(Arrays.asList(UrlInfoResponseGroup.values()));
        request.setUrl("www.bryght.com");
        
        UrlInfoResponse response = client.getUrlInfo(request);
        
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getResponse());
        Assert.assertNotNull(response.getResponse().getUrlInfoResult().get(0));
        Assert.assertNotNull(response.getResponse().getUrlInfoResult().get(0).getAlexa().getContactInfo());
        Assert.assertNotNull(response.getResponse().getUrlInfoResult().get(0).getAlexa().getContentData());
        Assert.assertNotNull(response.getResponse().getUrlInfoResult().get(0).getAlexa().getRelated());
        Assert.assertNotNull(response.getResponse().getUrlInfoResult().get(0).getAlexa().getTrafficData());
    }
    
    @Test
    public void testGetTrafficHistory() throws SignatureException, IOException, JAXBException {
        AlexaWebInformationServiceClient client = new AlexaWebInformationServiceClient(credentials);
        
        TrafficHistoryRequest request = new TrafficHistoryRequest();
        request.setUrl("www.bryght.com");
        request.setRange(20);
        
        Calendar start = GregorianCalendar.getInstance();
        start.set(Calendar.YEAR, 2015);
        start.set(Calendar.MONTH, 1);
        start.set(Calendar.DAY_OF_MONTH, 1);
        
        request.setStart(start.getTime());

        TrafficHistoryResponse response = client.getTrafficHistory(request);
       
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getResponse());
        Assert.assertNotNull(response.getResponse().getTrafficHistoryResult().get(0));
        Assert.assertNotNull(response.getResponse().getTrafficHistoryResult().get(0).getAlexa().getTrafficHistory());
    }
    
    @Test
    public void testCategoryBrowse() throws SignatureException, IOException, JAXBException {
        AlexaWebInformationServiceClient client = new AlexaWebInformationServiceClient(credentials);
        
        CategoryBrowseRequest request = new CategoryBrowseRequest();
        request.setResponseGroups(Arrays.asList(CategoryBrowseResponseGroup.values()));
        request.setPath("Top/Shopping");
        request.setDescriptions(Boolean.TRUE);

        CategoryBrowseResponse response = client.getCategoryBrowse(request);
        
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getResponse());
        Assert.assertNotNull(response.getResponse().getCategoryBrowseResult().get(0));
        Assert.assertNotNull(response.getResponse().getCategoryBrowseResult().get(0).getAlexa().getCategoryBrowse());
    }    
    
    @Test
    public void testCategoryListings() throws SignatureException, IOException, JAXBException {
        AlexaWebInformationServiceClient client = new AlexaWebInformationServiceClient(credentials);
        
        CategoryListingsRequest request = new CategoryListingsRequest();
        request.setPath("Top/Business/Automotive");
        request.setRecursive(Boolean.TRUE);
        request.setStart(1);;
        request.setCount(15);
        request.setSortBy(SortBy.Popularity);
        request.setDescriptions(Boolean.TRUE);

        CategoryListingsResponse response = client.getCategoryListings(request);
        
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getResponse());
        Assert.assertNotNull(response.getResponse().getCategoryListingsResult().get(0));
        Assert.assertNotNull(response.getResponse().getCategoryListingsResult().get(0).getAlexa().getCategoryListings());
    }
    
    @Test
    public void testSitesLinkingIn() throws SignatureException, IOException, JAXBException {
        AlexaWebInformationServiceClient client = new AlexaWebInformationServiceClient(credentials);
        
        SitesLinkingInRequest request = new SitesLinkingInRequest();
        request.setUrl("www.amazon.com");
        request.setStart(0);
        request.setCount(15);

        SitesLinkingInResponse response = client.getSitesLinkingIn(request);
        
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getResponse());
        Assert.assertNotNull(response.getResponse().getSitesLinkingInResult().get(0));
        Assert.assertNotNull(response.getResponse().getSitesLinkingInResult().get(0).getAlexa().getSitesLinkingIn());
    }
}
