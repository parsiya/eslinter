package lint;

import burp.IHttpRequestResponse;
import utils.ReqResp;
import utils.StringUtils;

import static burp.BurpExtender.log;
import static burp.BurpExtender.callbacks;

import java.net.URL;

import burp.Config;

/**
 * ProcessRequestTask processes each incoming request.
 */
public class ProcessRequestTask implements Runnable {

    private int toolFlag;
    private IHttpRequestResponse requestResponse;
    private Config extensionConfig;

    // Constructor.
    public ProcessRequestTask(
        int toolFlag,
        IHttpRequestResponse requestResponse,
        Config config
    ) {

        this.toolFlag = toolFlag;
        this.requestResponse = requestResponse;
        this.extensionConfig = config;
    }

    // This is how we process each incoming request.
    @Override
    public void run() {

        // This will be the thread identifier for logs.
        String threadURL = requestResponse.getHttpService().toString();
        log.debug("----------");
        final String toolName = callbacks.getToolName(toolFlag);
        // Some toolFlags have the same toolName. See table in `Config.java`.
        log.debug(
            "Inside the request thread for %s. Got a request. Tool: %s - Tool Flag: %d",
            threadURL,
            toolName,
            toolFlag
        );

        // Only process if the callbacks.getToolName(toolFlag) is in
        // processTools, otherwise return.
        if (!StringUtils.arrayContains(toolName, extensionConfig.processToolList)) {
            log.debug(
                "Inside the request thread for %s. %s is not in the process-tool-list, returning from ProcessRequestTask.",
                threadURL,
                toolName
            );
            return;
        }

        // Check if the request is in scope.
        if (extensionConfig.processInScope) {
            // Get the request URL.
            URL reqURL = ReqResp.getURL(requestResponse);
            if (!callbacks.isInScope(reqURL)) {
                // Request is not in scope, return.
                log.debug(
                    "Inside the request thread for %s. Request is not in scope, returning from ProcessRequestTask.",
                    threadURL
                );
                return;
            }
        }

        // Remove the specified headers (in Config's "removable-headers") from
        // the request.
        for (final String hdr : extensionConfig.headersToRemove) {
            requestResponse = ReqResp.removeHeader(true, requestResponse, hdr);
        }
        log.debug(
            "Inside the request thread for %s. Removed headers from the request, returning from ProcessRequestTask.",
            threadURL
        );

        // We are done here.
        log.debug("Inside the request thread for %s. Finished", threadURL);
        return;
    }
}