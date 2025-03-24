package com.business.cors2.endpoint.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.util.JSONPObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b> ResourceController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-03-24
 */

@Slf4j
@RestController
@RequestMapping("/api/users")
public class ResourceController {

    @GetMapping("/resources")
    public String userResources() {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode jsonObject = mapper.createObjectNode();

        jsonObject.put("name", "masonPark");
        return jsonObject.toString();
    }
}
