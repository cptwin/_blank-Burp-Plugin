package burp;

import java.net.URL;

public class ScanIssue implements IScanIssue
{
    private final IHttpRequestResponse requestResponse;
    private final String name;
    private final String severity;
    private final String confidence;
    private final String issueBackground;
    private final String issueDetail;
    private final String remediationBackground;
    private final String remediationDetail;
    private final int type;

    public ScanIssue(IHttpRequestResponse requestResponse,
                     String name,
                     String severity,
                     String confidence,
                     String issueBackground,
                     String issueDetail,
                     String remediationDetail)
    {
        this.requestResponse = requestResponse;
        this.name = name;
        this.severity = severity;
        this.confidence = confidence;
        this.issueBackground = issueBackground;
        this.issueDetail = issueDetail;
        this.remediationBackground = null;
        this.remediationDetail = remediationDetail;
        this.type = 0x0800000; //See http://portswigger.net/burp/help/scanner_issuetypes.html
    }

    public String getProtocol()
    {
        return requestResponse.getHttpService().getProtocol();
    }

    public String getHost()
    {
        return requestResponse.getHttpService().getHost();
    }

    public int getPort()
    {
        return requestResponse.getHttpService().getPort();
    }

    @Override
    public URL getUrl() {
        return null;
    }

    @Override
    public String getIssueName()
    {
        return this.name;
    }

    @Override
    public int getIssueType()
    {
        return this.type;
    }

    @Override
    public String getSeverity()
    {
        return this.severity;
    }

    @Override
    public String getConfidence()
    {
        return this.confidence;
    }

    @Override
    public String getIssueBackground()
    {
        return this.issueBackground;
    }

    @Override
    public String getRemediationBackground()
    {
        return this.remediationBackground;
    }

    @Override
    public String getIssueDetail()
    {
        return this.issueDetail;
    }

    @Override
    public String getRemediationDetail()
    {
        return this.remediationDetail;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        IHttpRequestResponse[] messages = { this.requestResponse };
        return messages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return this.requestResponse.getHttpService();
    }
}
