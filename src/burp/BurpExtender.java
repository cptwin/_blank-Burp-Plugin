package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    private final String version;
    private final String name;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout, stderr;

    public BurpExtender()
    {
        this.name = "UnderscoreBlank";
        this.version = "0.1.2 alpha";
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName(this.name + " " + this.version);

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.registerScannerCheck(this);

        callbacks.issueAlert(this.name + " " + this.version + " Passive Scanner check enabled");
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return checkForVuln(baseRequestResponse);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return checkForVuln(baseRequestResponse);
    }

    public List<IScanIssue> checkForVuln(IHttpRequestResponse baseRequestResponse) {
        String response = helpers.bytesToString(baseRequestResponse.getResponse());
        Pattern patternUnderscoreBlank = Pattern.compile(".*target=\"_blank\".*", Pattern.DOTALL);
        Matcher matcherUnderscoreBlank = patternUnderscoreBlank.matcher(response);
        Pattern patternRelOpener = Pattern.compile(".*rel=\"opener\".*", Pattern.DOTALL);
        Matcher matcherRelOpener = patternRelOpener.matcher(response);
        //Check match for html pages only
        if (matcherUnderscoreBlank.matches() && matcherRelOpener.matches()) {
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new UnderscoreBlankIssue(baseRequestResponse));
            return issues;
        }
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    class UnderscoreBlankIssue implements IScanIssue {

        private final IHttpRequestResponse requestResponse;

        public UnderscoreBlankIssue(IHttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
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
            return helpers.analyzeRequest(requestResponse).getUrl();
        }

        @Override
        public String getIssueName()
        {
            return "Underscore Blank Target Link";
        }

        @Override
        public int getIssueType()
        {
            return 0x08000000; //See http://portswigger.net/burp/help/scanner_issuetypes.html
        }

        @Override
        public String getSeverity()
        {
            return "Information"; // "High", "Medium", "Low", "Information" or "False positive"
        }

        @Override
        public String getConfidence()
        {
            return "Tentative"; //"Certain", "Firm" or "Tentative"
        }

        @Override
        public String getIssueBackground()
        {
            return "https://cptwin.lolnet.co.nz/";
        }

        @Override
        public String getRemediationBackground()
        {
            return "None";
        }

        @Override
        public String getIssueDetail()
        {
            return "If the link uses _blank and is user controlled then this could be used to perform phishing attacks.";
        }

        @Override
        public String getRemediationDetail()
        {
            return "Make sure to add relnoopener or better yet, remove _blank links.";
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
}
