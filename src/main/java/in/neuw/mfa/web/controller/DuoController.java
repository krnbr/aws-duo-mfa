package in.neuw.mfa.web.controller;

import in.neuw.mfa.config.props.DuoClientProperties;
import in.neuw.mfa.service.AWSCredService;
import in.neuw.mfa.service.DuoMfaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.net.URI;
import java.util.concurrent.TimeUnit;

import static org.springframework.http.HttpStatus.MOVED_PERMANENTLY;

@Controller
@RequestMapping("/duo/")
public class DuoController {

    @Autowired
    private DuoMfaService duoMfaService;

    @Autowired
    private AWSCredService awsCredService;

    @Autowired
    private DuoClientProperties duoClientProperties;

    @GetMapping
    public String index() {
        return "index";
    }

    @GetMapping("init")
    public ResponseEntity<Void> initMFA() {
        URI location = duoMfaService.initiateMFA(duoClientProperties.getUsername());
        ResponseEntity responseEntity = new ResponseEntity(headersForRedirect(location), MOVED_PERMANENTLY);
        return responseEntity;
    }

    @ResponseBody
    @GetMapping("mfa/callback")
    public ResponseEntity<Void> callback(@RequestParam("duo_code") final String duoMfaCode) {
        URI signInUrlLocation = URI.create(awsCredService.getSignInUrl(duoMfaCode));
        ResponseEntity responseEntity = new ResponseEntity(headersForRedirect(signInUrlLocation), MOVED_PERMANENTLY);
        return responseEntity;
    }

    private HttpHeaders headersForRedirect(URI uri) {
        CacheControl noCache = CacheControl
                .noCache()
                .noStore()
                .maxAge(0, TimeUnit.MICROSECONDS)
                .noTransform()
                .mustRevalidate();

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(uri);
        headers.setExpires(0);
        headers.setCacheControl(noCache);
        headers.setPragma("no-cache");
        return headers;
    }

}
