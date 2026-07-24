#!/usr/bin/env julia
#=
This script serves as an AI‑powered URL safety analyst, intended to be called from
Go (or any orchestrator). It loads three pre‑trained ML models, extracts features
from a URL and its IP address, and outputs a structured JSON risk assessment.

Usage:
    julia julia_agent.jl <models_directory> <url> <ip>

Requirements:
    - The models must be saved with MLJ.save() as .jlso files:
        link_health_model.jlso
        ip_reputation_model.jlso
        url_shortener_model.jlso
=#

using JSON
using MLJ
using URIs

# ------------------------------------------------------------------------
# Data structures matching the Go side
# ------------------------------------------------------------------------

"""
    AnalysisFeatures

Stores all features extracted from a URL and its hosting IP.
"""
struct AnalysisFeatures
    url_length::Int
    num_special_chars::Int
    has_ip::Bool
    has_redirect::Bool
    tld_risk::Float64
    entropy::Float64
    keyword_matches::Int
    domain_age::Int          # could be retrieved from WHOIS, defaults to 365
    ssl_verified::Bool       # could be verified via certificate chain
    asn_reputation::Float64  # ASN trust score, 0 (bad) – 1 (perfect)
end

"""
    AIResult

Final assessment returned to the caller. All fields have safe defaults
so that even a partial analysis can be serialised.
"""
struct AIResult
    is_safe::Bool
    confidence::Float64
    risk_level::String
    is_shortened::Bool
    health_score::Float64
    threats::Vector{String}
    recommendations::Vector{String}
    error::String
end

# ------------------------------------------------------------------------
# Model loading (models are loaded only when the path is known)
# ------------------------------------------------------------------------

"""
    load_model(path::String, name::String)

Load a single `.jlso` model using MLJ.load. Returns the loaded machine.
Throws a descriptive error if loading fails.
"""
function load_model(path::String, name::String)
    fullpath = joinpath(path, name)
    try
        @info "Loading model $fullpath"
        return MLJ.load(fullpath)
    catch e
        error("Failed to load model $fullpath: $e")
    end
end

"""
    load_all_models(models_dir::String)

Loads all three required models and returns them as a tuple.
"""
function load_all_models(models_dir::String)
    link_health   = load_model(models_dir, "link_health_model.jlso")
    ip_reputation = load_model(models_dir, "ip_reputation_model.jlso")
    url_shortener = load_model(models_dir, "url_shortener_model.jlso")
    return link_health, ip_reputation, url_shortener
end

# ------------------------------------------------------------------------
# Feature extraction
# ------------------------------------------------------------------------

"""
    assess_tld_risk(host::String) -> Float64

Returns a risk score (0.0–1.0) based on the top‑level domain of the host.
"""
function assess_tld_risk(host::String)
    high_risk   = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]
    medium_risk = [".club", ".work", ".online", ".site", ".click"]

    for tld in high_risk
        endswith(host, tld) && return 0.9
    end
    for tld in medium_risk
        endswith(host, tld) && return 0.6
    end
    return 0.1
end

"""
    calculate_entropy(s::AbstractString) -> Float64

Shannon entropy of the string, used to detect obfuscation.
"""
function calculate_entropy(s::AbstractString)
    counts = Dict{Char,Int}()
    for c in s
        counts[c] = get(counts, c, 0) + 1
    end
    entropy = 0.0
    len = length(s)
    len == 0 && return 0.0
    for cnt in values(counts)
        p = cnt / len
        entropy -= p * log(2, p)   # explicit base‑2 logarithm
    end
    return entropy
end

"""
    extract_features(url::String, ip::String) -> AnalysisFeatures

Parses the URL, extracts all required features, and returns an `AnalysisFeatures`
struct. Handles missing host gracefully.
"""
function extract_features(url::String, ip::String)
    # Parse URI; invalid URLs are caught by the outer exception handler
    parsed = URIs.URI(url)

    host = something(parsed.host, "")  # handle mailto: or opaque URIs

    url_length = length(url)
    num_special_chars = count(c -> c in ['@', '%', '&', '=', '?', '#'], url)
    has_ip = occursin(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)  # exact IP host
    has_redirect = occursin(r"(redirect|url|goto|next)=", lowercase(url))

    tld_risk = isempty(host) ? 0.5 : assess_tld_risk(host)   # unknown host → neutral risk

    entropy = calculate_entropy(url)

    suspicious = ["login", "verify", "account", "secure", "bank", "paypal", "update", "confirm"]
    keyword_matches = count(kw -> occursin(kw, lowercase(url)), suspicious)

    # Placeholders for data that would need external calls – kept as sensible defaults.
    domain_age = 365
    ssl_verified = true        # assumes HTTPS is validated by the caller
    asn_reputation = 0.8

    return AnalysisFeatures(url_length, num_special_chars, has_ip, has_redirect,
                            tld_risk, entropy, keyword_matches,
                            domain_age, ssl_verified, asn_reputation)
end

"""
    features_for_link_health(f::AnalysisFeatures) -> Matrix

Builds the feature matrix expected by the link‑health model.
"""
function features_for_link_health(f::AnalysisFeatures)
    return reshape([
        f.url_length, f.num_special_chars, Float64(f.has_ip),
        Float64(f.has_redirect), f.tld_risk, f.entropy,
        f.keyword_matches, f.domain_age, Float64(f.ssl_verified),
        f.asn_reputation,
    ], 1, :)
end

"""
    features_for_url_shortener(f::AnalysisFeatures) -> Matrix

Builds the feature matrix for the shortened‑URL detector.
"""
function features_for_url_shortener(f::AnalysisFeatures)
    # In a real system these would be model‑specific features.
    # Here we reuse the same vector, but split to allow future differentiation.
    return features_for_link_health(f)
end

"""
    features_for_ip_reputation(ip::String) -> Matrix

Converts an IPv4 address into a small feature vector (octets + length).
Returns a zero matrix for empty or invalid IPs.
"""
function features_for_ip_reputation(ip::String)
    if isempty(strip(ip))
        # no IP provided → neutral placeholder
        return reshape([0, 0, 0, 0, 0], 1, :)
    end
    parts = split(ip, '.')
    if length(parts) != 4
        # malformed, return neutral features
        return reshape([0, 0, 0, 0, length(ip)], 1, :)
    end
    octets = try
        parse.(Int, parts)
    catch
        # non‑numeric octets → neutral
        return reshape([0, 0, 0, 0, length(ip)], 1, :)
    end
    return reshape([octets..., length(ip)], 1, :)
end

# ------------------------------------------------------------------------
# Prediction helpers
# ------------------------------------------------------------------------

"""
    safe_predict(model, features)

Calls MLJ.predict and returns the first element of the result.
If prediction fails, throws an error with context.
"""
function safe_predict(model, features)
    preds = MLJ.predict(model, features)
    return first(preds)   # assumes the model returns an iterable
end

# ------------------------------------------------------------------------
# Threat and recommendation generation
# ------------------------------------------------------------------------

function generate_threats(f::AnalysisFeatures, health_score::Float64, ip_risk::Float64)
    threats = String[]
    f.has_ip              && push!(threats, "Uses IP address instead of domain name")
    f.tld_risk > 0.7      && push!(threats, "High-risk TLD detected")
    f.entropy > 4.5       && push!(threats, "High URL entropy (possible obfuscation)")
    f.keyword_matches > 3 && push!(threats, "Multiple suspicious keywords found")
    ip_risk > 0.7         && push!(threats, "Suspicious IP reputation")
    health_score < 0.3    && push!(threats, "Very low link health score")
    return threats
end

function generate_recommendations(is_safe::Bool, risk_level::String, is_shortened::Bool)
    recs = String[]
    if !is_safe
        push!(recs, "DO NOT visit this link", "Delete the message immediately")
    end
    risk_level == "CRITICAL" && push!(recs, "Report to authorities immediately")
    is_shortened && push!(recs, "URL appears to be shortened - use caution")
    risk_level in ("MEDIUM", "HIGH") && push!(recs, "Verify through official channels before clicking")
    push!(recs, "Enable two-factor authentication on your accounts")
    return recs
end

# ------------------------------------------------------------------------
# Core analysis logic
# ------------------------------------------------------------------------

"""
    analyze_link_health(models::Tuple, url::String, ip::String) -> AIResult

Given a tuple of three loaded models, extracts features, runs predictions,
and assembles the final `AIResult`.
"""
function analyze_link_health(models::Tuple, url::String, ip::String)
    link_health_model, ip_reputation_model, url_shortener_model = models

    features = extract_features(url, ip)

    # predictions (type‑stable assignments)
    health_score = safe_predict(link_health_model, features_for_link_health(features))
    is_shortened = safe_predict(url_shortener_model, features_for_url_shortener(features)) > 0.5
    ip_risk      = safe_predict(ip_reputation_model, features_for_ip_reputation(ip))

    # overall confidence (health plus IP trust)
    overall_confidence = (health_score + (1.0 - ip_risk)) / 2.0
    is_safe = overall_confidence > 0.7

    # risk level mapping
    risk_level = if overall_confidence < 0.3
        "CRITICAL"
    elseif overall_confidence < 0.5
        "HIGH"
    elseif overall_confidence < 0.7
        "MEDIUM"
    else
        "LOW"
    end

    threats = generate_threats(features, health_score, ip_risk)
    recommendations = generate_recommendations(is_safe, risk_level, is_shortened)

    return AIResult(is_safe, overall_confidence, risk_level, is_shortened,
                    health_score, threats, recommendations, "")
end

# ------------------------------------------------------------------------
# Main entry point – argument parsing and JSON output
# ------------------------------------------------------------------------

function main()
    if length(ARGS) != 3
        println(stderr, "Usage: julia julia_agent.jl <models_directory> <url> <ip>")
        exit(1)
    end

    models_dir = ARGS[1]
    url = ARGS[2]
    ip  = ARGS[3]

    # Basic input validation
    if isempty(strip(url))
        output_error("Empty URL provided")
        return
    end

    try
        # Validate the URL by attempting to parse it
        URIs.URI(url)
    catch e
        output_error("Invalid URL format: $e")
        return
    end

    # Load models *after* we have the path
    local models
    try
        models = load_all_models(models_dir)
    catch e
        output_error("Model loading failed: $e")
        return
    end

    # Run analysis and print JSON result
    try
        result = analyze_link_health(models, url, ip)
        result_dict = Dict(
            "is_safe" => result.is_safe,
            "confidence" => result.confidence,
            "risk_level" => result.risk_level,
            "is_shortened" => result.is_shortened,
            "health_score" => result.health_score,
            "threats" => result.threats,
            "recommendations" => result.recommendations,
            "error" => result.error,
        )
        println(JSON.json(result_dict))
    catch e
        output_error("Analysis failed: $e")
    end
end

"""
    output_error(msg::String)

Prints a JSON error response and then exits with a non‑zero code.
"""
function output_error(msg::String)
    error_result = Dict(
        "error" => msg,
        "is_safe" => false,
        "confidence" => 0.0,
        "risk_level" => "UNKNOWN",
        "is_shortened" => false,
        "health_score" => 0.0,
        "threats" => ["Analysis failed"],
        "recommendations" => ["Use extreme caution", "Manual verification required"],
    )
    println(JSON.json(error_result))
    exit(1)
end

# ------------------------------------------------------------------------
# Run when invoked as a script
# ------------------------------------------------------------------------
if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
