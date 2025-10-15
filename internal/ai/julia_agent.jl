using JSON
using MLJ
using HTTP
using URIs

# Load pre-trained models
const LINK_HEALTH_MODEL = MLJ.load(joinpath(@__DIR__, "link_health_model.jlso"))
const IP_REPUTATION_MODEL = MLJ.load(joinpath(@__DIR__, "ip_reputation_model.jlso"))
const URL_SHORTENER_MODEL = MLJ.load(joinpath(@__DIR__, "url_shortener_model.jlso"))

struct AnalysisFeatures
    url_length::Int
    num_special_chars::Int
    has_ip::Bool
    has_redirect::Bool
    tld_risk::Float64
    entropy::Float64
    keyword_matches::Int
    domain_age::Int
    ssl_verified::Bool
    asn_reputation::Float64
end

struct AIResult
    is_safe::Bool
    confidence::Float64
    risk_level::String
    is_shortened::Bool
    health_score::Float64
    threats::Vector{String}
    recommendations::Vector{String}
end

function analyze_link_health(url::String, ip::String="")::AIResult
    features = extract_features(url, ip)
    
    # Predict using ML models
    health_score = MLJ.predict(LINK_HEALTH_MODEL, features_to_matrix(features))[1]
    is_shortened = MLJ.predict(URL_SHORTENER_MODEL, features_to_matrix(features))[1] > 0.5
    ip_risk = ip != "" ? MLJ.predict(IP_REPUTATION_MODEL, ip_features(ip))[1] : 0.5
    
    # Calculate overall safety
    overall_confidence = (health_score + (1 - ip_risk)) / 2
    is_safe = overall_confidence > 0.7
    
    # Determine risk level
    risk_level = if overall_confidence < 0.3
        "CRITICAL"
    elseif overall_confidence < 0.5
        "HIGH"
    elseif overall_confidence < 0.7
        "MEDIUM"
    else
        "LOW"
    end
    
    # Generate threats and recommendations
    threats = generate_threats(features, health_score, ip_risk)
    recommendations = generate_recommendations(is_safe, risk_level, is_shortened)
    
    return AIResult(is_safe, overall_confidence, risk_level, is_shortened, health_score, threats, recommendations)
end

function extract_features(url::String, ip::String)::AnalysisFeatures
    parsed_uri = URIs.URI(url)
    
    url_length = length(url)
    num_special_chars = count(c -> c in ['@', '%', '&', '=', '?', '#'], url)
    has_ip = occursin(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url)
    has_redirect = occursin(r"(redirect|url|goto|next)=", lowercase(url))
    
    # TLD risk assessment
    tld_risk = assess_tld_risk(parsed_uri)
    
    # URL entropy (complexity measure)
    entropy = calculate_entropy(url)
    
    # Suspicious keywords
    suspicious_keywords = ["login", "verify", "account", "secure", "bank", "paypal", "update", "confirm"]
    keyword_matches = count(kw -> occursin(kw, lowercase(url)), suspicious_keywords)
    
    # Placeholder values (would need actual data sources)
    domain_age = 365  # Would fetch from WHOIS
    ssl_verified = true  # Would verify SSL certificate
    asn_reputation = 0.8  # Would check ASN reputation
    
    return AnalysisFeatures(url_length, num_special_chars, has_ip, has_redirect, tld_risk, 
                           entropy, keyword_matches, domain_age, ssl_verified, asn_reputation)
end

function assess_tld_risk(uri::URIs.URI)::Float64
    high_risk_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]
    medium_risk_tlds = [".club", ".work", ".online", ".site", ".click"]
    
    host = string(uri.host)
    
    for tld in high_risk_tlds
        if endswith(host, tld)
            return 0.9
        end
    end
    
    for tld in medium_risk_tlds
        if endswith(host, tld)
            return 0.6
        end
    end
    
    return 0.1
end

function calculate_entropy(s::String)::Float64
    freq_dict = Dict{Char,Int}()
    for c in s
        freq_dict[c] = get(freq_dict, c, 0) + 1
    end
    
    entropy = 0.0
    len = length(s)
    for count in values(freq_dict)
        p = count / len
        entropy -= p * log2(p)
    end
    
    return entropy
end

function features_to_matrix(features::AnalysisFeatures)
    return reshape([features.url_length, features.num_special_chars, 
                   float(features.has_ip), float(features.has_redirect),
                   features.tld_risk, features.entropy, features.keyword_matches,
                   features.domain_age, float(features.ssl_verified), 
                   features.asn_reputation], 1, :)
end

function ip_features(ip::String)
    # Extract features from IP address for reputation analysis
    octets = parse.(Int, split(ip, '.'))
    return reshape([octets..., length(ip)], 1, :)
end

function generate_threats(features::AnalysisFeatures, health_score::Float64, ip_risk::Float64)::Vector{String}
    threats = String[]
    
    if features.has_ip
        push!(threats, "Uses IP address instead of domain name")
    end
    
    if features.tld_risk > 0.7
        push!(threats, "High-risk TLD detected")
    end
    
    if features.entropy > 4.5
        push!(threats, "High URL entropy (possible obfuscation)")
    end
    
    if features.keyword_matches > 3
        push!(threats, "Multiple suspicious keywords found")
    end
    
    if ip_risk > 0.7
        push!(threats, "Suspicious IP reputation")
    end
    
    if health_score < 0.3
        push!(threats, "Very low link health score")
    end
    
    return threats
end

function generate_recommendations(is_safe::Bool, risk_level::String, is_shortened::Bool)::Vector{String}
    recommendations = String[]
    
    if !is_safe
        push!(recommendations, "DO NOT visit this link")
        push!(recommendations, "Delete the message immediately")
    end
    
    if risk_level == "CRITICAL"
        push!(recommendations, "Report to authorities immediately")
    end
    
    if is_shortened
        push!(recommendations, "URL appears to be shortened - use caution")
    end
    
    if risk_level in ["MEDIUM", "HIGH"]
        push!(recommendations, "Verify through official channels before clicking")
    end
    
    push!(recommendations, "Enable two-factor authentication on your accounts")
    
    return recommendations
end

# Main function to handle requests from Go
function main()
    if length(ARGS) != 2
        println("Usage: julia jl [url] [ip]")
        exit(1)
    end
    
    url = ARGS[1]
    ip = ARGS[2]
    
    try
        result = analyze_link_health(url, ip)
        result_json = JSON.json(Dict(
            "is_safe" => result.is_safe,
            "confidence" => result.confidence,
            "risk_level" => result.risk_level,
            "is_shortened" => result.is_shortened,
            "health_score" => result.health_score,
            "threats" => result.threats,
            "recommendations" => result.recommendations
        ))
        println(result_json)
    catch e
        error_result = JSON.json(Dict(
            "error" => string(e),
            "is_safe" => false,
            "confidence" => 0.0,
            "risk_level" => "UNKNOWN",
            "is_shortened" => false,
            "health_score" => 0.0,
            "threats" => ["Analysis failed"],
            "recommendations" => ["Use extreme caution", "Manual verification required"]
        ))
        println(error_result)
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
