package com.business.security.business.endpoint.authorization;

import com.business.security.business.endpoint.authorization.model.AccountVo;
import com.business.security.business.service.authorization.DataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * <b> MethodAuthorization2Controller </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-05-12
 */

@Slf4j
@ConditionalOnProperty(value = "security.type", havingValue = "method-authorization2", matchIfMissing = false)

@RequiredArgsConstructor
@RestController
public class MethodAuthorization2Controller {

    private final DataService service;

    @PostMapping("/write-list")
    public List<AccountVo> writeList(@RequestBody List<AccountVo> reqList) {
        return service.writeList(reqList);
    }

    @PostMapping("/write-map")
    public Map<String, AccountVo> writeMap(@RequestBody List<AccountVo> reqList) {
        Map<String, AccountVo> map = reqList.stream()
                .collect(Collectors.toMap(
                        AccountVo::getOwner
                        , (vo) -> vo));
        return service.writeMap(map);
    }

    @GetMapping("/readList")
    public List<AccountVo> readList() {
        return service.readList();
    }

    @GetMapping("/readMap")
    public Map<String, AccountVo> readMap() {

        return service.readMap();
    }
}
