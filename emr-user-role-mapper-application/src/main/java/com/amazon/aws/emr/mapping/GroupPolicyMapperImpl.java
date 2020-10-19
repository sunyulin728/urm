package com.amazon.aws.emr.mapping;

import com.amazon.aws.emr.ApplicationConfiguration;
import com.amazon.aws.emr.common.system.PrincipalResolver;
import com.amazon.aws.emr.common.system.factory.PrincipalResolverFactory;
import com.amazon.aws.emr.model.PrincipalRoleMapping;
import com.amazon.aws.emr.model.PrincipalRoleMappings;
import com.amazon.aws.emr.rolemapper.UserRoleMapperProvider;
import com.amazonaws.AmazonClientException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.PolicyDescriptorType;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Default implementation to read mapping from S3 in JSON format.
 * The format for the JSON can be found in {@code PrincipalRoleMappings}.
 */
@NoArgsConstructor
@Slf4j
public class GroupPolicyMapperImpl implements UserRoleMapperProvider {

    static final AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
    private static final Gson GSON = new GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.UPPER_CAMEL_CASE)
            .setPrettyPrinting()
            .create();


    private final Map<String, String> groupPolicyarnMapping = new HashMap<>();
    private final Map<String, AssumeRoleRequest> userRoleMapping = new HashMap<>();

    private String bucketName;
    private String key;
    private String etag;
    private String adminRoleArn;
    private PrincipalResolver principalResolver;

    public GroupPolicyMapperImpl(String bucketName, String key, PrincipalResolver principalResolver) {
        this.bucketName = Objects.requireNonNull(bucketName);

        // TODO: We may relax this to allow null value. In case of null value, parse all keys under above bucket
        this.key = Objects.requireNonNull(key);
        this.etag = null;
        this.principalResolver = Objects.requireNonNull(principalResolver);
    }

    /**
     * Inits the mapper.
     */
    public void init() {
    }

    /**
     * @param username the user whose mapping we want.
     *                 Username mapping takes precedence over group name mapping.
     *                 If multiple group name mappings exist, then the first one is returned.
     * @return an {@code Optional} of {@code AssumeRoleRequest}
     */
    public Optional<AssumeRoleRequest> getMapping(String username) {
        // Consult if we have a mapping with username
        AssumeRoleRequest assumeRoleRequest = userRoleMapping.get(username);
        if (assumeRoleRequest != null) {
            log.debug("Usermapping found for {} as {}", username, assumeRoleRequest);
            return Optional.of(assumeRoleRequest);
        }
        log.debug("No user mapping found for {}. Checking with group mapping.", username);

        if (adminRoleArn == null) {
            log.debug("No admin role found.");
            return null;
        }

        Optional<List<String>> groups = principalResolver.getGroups(username);

        HashSet<PolicyDescriptorType> policyarnSet = new HashSet<>();

        for (String group : groups.orElse(Collections.emptyList())) {
            String policyarn = groupPolicyarnMapping.get(group);
            if (policyarn != null) {
                log.debug("group mapping found for {} as {}", group, policyarn);
                PolicyDescriptorType policy = new PolicyDescriptorType().withArn(policyarn);
                policyarnSet.add(policy);
            }
        }

        if (policyarnSet.size() == 0) {
            log.debug("No user mapping found for {}. Checking with group mapping.", username);
            return null;
        }

        assumeRoleRequest = new AssumeRoleRequest()
                .withRoleArn(adminRoleArn)
                .withPolicyArns(policyarnSet)
                .withRoleSessionName(username); // Use username as session name*/

        userRoleMapping.put(username, assumeRoleRequest);
        log.info("Mapped {} to {}", username, assumeRoleRequest);

        return Optional.of(assumeRoleRequest);
    }

    /**
     * Checks if the S3 source has a new mapping since the last refresh interval.
     * If a new mapping is present then reloads mappings in a thread safe manner.
     */
    public void refresh() {
        log.debug("Checking if need to load mapping again from S3 from {}/{}", bucketName, key);
        ObjectMetadata objectMetadata = s3Client.getObjectMetadata(bucketName, key);
        if (objectMetadata.getETag().equals(etag)) {
            log.debug("Nothing to do as current etag {} matches the last one.", objectMetadata.getETag());
        } else {
            log.info("Seems we have new mapping - reload it.");
            readMapping();
            log.info("Done with the reload.");
        }
    }

    private void readMapping() {
        log.info("Load the mapping from S3 from {}/{}", bucketName, key);
        try (S3Object s3object = s3Client.getObject(new GetObjectRequest(
                bucketName, key))){
            S3ObjectInputStream s3InputStream = s3object.getObjectContent();
            String jsonString = null;
            try {
                jsonString = getS3FileAsString(s3InputStream);
            } catch (IOException e) {
                throw new RuntimeException("Could not fetch the mapping file from S3.");
            }
            // Update the ETag
            etag = s3object.getObjectMetadata().getETag();
            populateMaps(jsonString);
        } catch (AmazonClientException ace) {
            log.error("AWS exception {}", ace.getMessage(), ace);
        } catch (IOException e) {
            log.error("Could not load mapping from S3", e);
        }
    }

    /**
     * Populates the internal maps with the mapping in S3.
     * The format for the JSON can be found in {@code PrincipalRoleMappings}.
     *
     * @param jsonString the S3 JSON represented as a String.
     */
    private void populateMaps(String jsonString) {
        log.info("Received the following JSON {}", jsonString);
        PrincipalRoleMappings principalRoleMappings = GSON.fromJson(jsonString, PrincipalRoleMappings.class);
        // Clear the old mapping now since we found a new valid mapping!
        groupPolicyarnMapping.clear();
        userRoleMapping.clear();

        for (PrincipalRoleMapping principalRoleMapping : principalRoleMappings.getPrincipalRoleMappings()) {
            if (principalRoleMapping == null) {
                log.info("Invalid record!");
                continue;
            }

            String admin = principalRoleMapping.getAdminRoleArn();
            if (admin == null) {
                String principal = principalRoleMapping.getGroupname();
                if (principal == null) {
                    log.info("Invalid record containing no groupname");
                    continue;
                }

                String policyArn = principalRoleMapping.getPolicyArn();
                if (policyArn == null) {
                    log.info("Invalid record containing no policyArn");
                    continue;
                }

                groupPolicyarnMapping.put(principal, policyArn);
                log.info("Mapped {} to {}", principal, policyArn);
            } else {
                adminRoleArn = admin;
            }
        }
    }

    private static String getS3FileAsString(InputStream is) throws IOException {
        if (is == null)
            return null;
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }
}

