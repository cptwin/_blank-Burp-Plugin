package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpUtilities implements IScannerCheck {

    private IExtensionHelpers helpers;

    public BurpUtilities(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        /*boolean names = existingIssue.getIssueName().equals(newIssue.getIssueName());
        boolean urls = existingIssue.getUrl().equals(newIssue.getUrl());

        if(names && urls)
        {
            return -1;
        }
        return 0;*/
        return -1;
    }
}
