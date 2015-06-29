/*
 * _=_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_=
 * Repose
 * _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
 * Copyright (C) 2010 - 2015 Rackspace US, Inc.
 * _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_=_
 */
package org.openrepose.filters.custom.oauthauthorization

import java.net.URL
import java.util.UUID

import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.core.LoggerContext
import org.apache.logging.log4j.test.appender.ListAppender
import org.junit.runner.RunWith
import org.mockito.{ArgumentCaptor, Matchers, Mockito}
import org.openrepose.core.services.config.ConfigurationService
import org.openrepose.core.services.datastore.{Datastore, DatastoreService}
import org.openrepose.core.services.serviceclient.akka.AkkaServiceClient
import org.openrepose.filters.custom.oauthauthorization.config.OAuthAuthorizationConfig
import org.scalatest._
import org.scalatest.junit.JUnitRunner
import org.scalatest.mock.MockitoSugar
import org.springframework.mock.web.{MockFilterChain, MockFilterConfig, MockHttpServletRequest, MockHttpServletResponse}

import scala.collection.JavaConversions._

@RunWith(classOf[JUnitRunner])
class OAuthAuthorizationFilterTest extends FunSpec with BeforeAndAfterAll with BeforeAndAfter with GivenWhenThen with org.scalatest.Matchers with MockitoSugar {
  var filter: OAuthAuthorizationFilter = _
  var config: OAuthAuthorizationConfig = _
  var servletRequest: MockHttpServletRequest = _
  var servletResponse: MockHttpServletResponse = _
  var filterChain: MockFilterChain = _
  var mockConfigService: ConfigurationService = _
  var mockFilterConfig: MockFilterConfig = _
  var mockAkkaServiceClient: AkkaServiceClient = _
  var mockDatastoreService: DatastoreService = _
  var mockDatastore: Datastore = _
  var totalMessages: Int = _
  var listAppender: ListAppender = _

  override def beforeAll() {
    System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
      "com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl")
  }

  before {
    servletRequest = new MockHttpServletRequest
    servletResponse = new MockHttpServletResponse
    filterChain = new MockFilterChain
    mockConfigService = mock[ConfigurationService]
    mockAkkaServiceClient = mock[AkkaServiceClient]
    mockDatastoreService = mock[DatastoreService]
    mockDatastore = mock[Datastore]
    mockFilterConfig = new MockFilterConfig("OAuthAuthorizationFilter")
    config = new OAuthAuthorizationConfig
    config.setEnclaveHeaderName("X-Auth-Token")
    config.setClientId(UUID.randomUUID.toString)
    config.setClientSecret(UUID.randomUUID.toString)
    config.setOauthRedirectUri("https://test.openrepose.org/callback")
    config.setRequestedScope("requested:scope")
    config.setOauthAuthorizeUri("https://oauth.openrepose.org/login/oauth/authorize")
    config.setOauthAccessTokenUri("https://oauth.openrepose.org/login/oauth/access_token")
    val ctx = LogManager.getContext(false).asInstanceOf[LoggerContext]
    listAppender = ctx.getConfiguration.getAppender("List0").asInstanceOf[ListAppender].clear
    Mockito.when(mockDatastore.get(Matchers.anyString)).thenReturn(null, Nil: _*)
    Mockito.when(mockDatastoreService.getDefaultDatastore).thenReturn(mockDatastore)
    filter = new OAuthAuthorizationFilter(mockConfigService, mockAkkaServiceClient, mockDatastoreService)
  }

  after {
    if (filter.isInitialized) filter.destroy()
  }

  describe("when the configuration is updated") {
    it("should become initialized") {
      Given("an un-initialized filter and the default configuration")
      !filter.isInitialized

      When("the configuration is updated")
      filter.configurationUpdated(config)

      Then("the filter should be initialized")
      filter.isInitialized
      val events = listAppender.getEvents.toList.map(_.getMessage.getFormattedMessage)
      events.count(_.contains("Update   message: ")) shouldBe totalMessages
    }
  }

  describe("when initializing the filter") {
    it("should initialize the configuration to the default configuration") {
      Given("an un-initialized filter and a mock'd Filter Config")
      !filter.isInitialized
      val argumentCaptor = ArgumentCaptor.forClass(classOf[URL])

      When("the filter is initialized")
      filter.init(mockFilterConfig)

      Then("the filter should register with the ConfigurationService")
      Mockito.verify(mockConfigService).subscribeTo(
        Matchers.eq("OAuthAuthorizationFilter"),
        Matchers.eq("oauth-authorization.cfg.xml"),
        argumentCaptor.capture,
        Matchers.eq(filter),
        Matchers.eq(classOf[OAuthAuthorizationConfig]))

      argumentCaptor.getValue.toString.endsWith("/META-INF/schema/config/oauth-authorization.xsd")
    }
    it("should initialize the configuration to the given configuration") {
      Given("an un-initialized filter and a mock'd Filter Config")
      !filter.isInitialized
      mockFilterConfig.addInitParameter("filter-config", "another-name.cfg.xml")

      When("the filter is initialized")
      filter.init(mockFilterConfig)

      Then("the filter should register with the ConfigurationService")
      Mockito.verify(mockConfigService).subscribeTo(
        Matchers.anyString,
        Matchers.eq("another-name.cfg.xml"),
        Matchers.any(classOf[URL]),
        Matchers.any(classOf[OAuthAuthorizationFilter]),
        Matchers.eq(classOf[OAuthAuthorizationConfig]))
    }
  }

  describe("when destroying the filter") {
    it("should unregister the configuration from the configuration service") {
      Given("an un-initialized filter and a mock'd Filter Config")
      !filter.isInitialized
      mockFilterConfig.addInitParameter("filter-config", "another-name.cfg.xml")

      When("the filter is initialized and destroyed")
      filter.init(mockFilterConfig)
      filter.destroy()

      Then("the filter should unregister with the ConfigurationService")
      Mockito.verify(mockConfigService).unsubscribeFrom("another-name.cfg.xml", filter)
    }
  }

  describe("when the filter is accessed") {
    ignore("should log the messages") {
      Given("a request")
      servletRequest.setRequestURI("/path/to/bad")
      servletRequest.setMethod("GET")
      filter.configurationUpdated(config)

      When("the resource is requested")
      filter.doFilter(servletRequest, servletResponse, filterChain)

      Then("the configured messages should be logged.")
      val events = listAppender.getEvents.toList.map(_.getMessage.getFormattedMessage)
      events.count(_.contains("Update   message: ")) shouldBe totalMessages
      events.count(_.contains("Request  message: ")) shouldBe totalMessages
      events.count(_.contains("Response message: ")) shouldBe totalMessages
    }
  }
}
