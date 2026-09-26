// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AEra Profile NFT
 * @author AEra Team
 * @notice Production-ready ERC-721 profile NFT for Base mainnet (chainId 8453)
 *         This is the PUBLIC/VISIBLE profile NFT (not the soulbound auth NFT "AEra Identity")
 * 
 * ============ OpenSea Compatibility ============
 * OpenSea reads the `tokenURI(tokenId)` function to fetch metadata JSON.
 * The JSON should follow OpenSea's metadata standard:
 * {
 *   "name": "...",
 *   "description": "...",
 *   "image": "...",
 *   "attributes": [...]
 * }
 * 
 * Additionally implements:
 * - EIP-4906 for metadata update events (faster OpenSea indexing)
 * - contractURI() for collection-level metadata (royalties, description)
 * 
 * ============ Privacy Opt-In Design ============
 * By default, all tokens are PRIVATE. This means:
 * - tokenURI returns: {basePrivateURI}/{tokenId}.json (placeholder/hidden metadata)
 * - Only when the token owner explicitly calls `setVisibility(tokenId, true)`,
 *   the metadata becomes PUBLIC: {basePublicURI}/{tokenId}.json
 * - This protects users from unwanted exposure of their identity data.
 * - A delegate can be set per-token to allow apps to toggle visibility on behalf of the user.
 * - Delegate is automatically cleared on transfer (security feature).
 * 
 * ============ Identity NFT Design ============
 * - One NFT per wallet enforced (Sybil protection)
 * - Soulbound mode available (admin can enable to block transfers)
 * - In soulbound mode, approvals are also blocked for clear UX
 */

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/interfaces/IERC4906.sol";

contract AEraProfile is ERC721, AccessControl, Pausable, IERC4906 {
    using Strings for uint256;

    // ============ Roles ============
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // ============ Custom Errors ============
    error NotTokenOwner();
    error NotTokenOwnerOrDelegate();
    error TokenDoesNotExist();
    error SoulboundTransferBlocked();
    error SoulboundApprovalBlocked();
    error ZeroAddress();
    error InvalidTokenId();
    error AlreadyHasProfile();

    // ============ Events ============
    event Minted(address indexed to, uint256 indexed tokenId);
    event Burned(uint256 indexed tokenId);
    event VisibilityChanged(uint256 indexed tokenId, bool isPublic);
    event DelegateChanged(uint256 indexed tokenId, address indexed delegate);
    event BaseURIsChanged(string basePublicURI, string basePrivateURI);
    event SchemaVersionChanged(uint256 indexed version);
    event TokenSchemaVersionChanged(uint256 indexed tokenId, uint256 indexed version);
    event SoulboundModeChanged(bool enabled);

    // ============ Storage ============
    
    /// @notice Counter for sequential token IDs (starts at 1)
    uint256 private _nextTokenId;

    /// @notice Base URI for public metadata
    string public basePublicURI;

    /// @notice Base URI for private/placeholder metadata
    string public basePrivateURI;

    /// @notice Contract-level metadata URI for OpenSea (internal storage)
    string private _contractURI;

    /// @notice Global metadata schema version
    uint256 public metadataSchemaVersion;

    /// @notice If true, tokens cannot be transferred (except mint/burn)
    bool public soulboundMode;

    /// @notice Visibility flag per token: true = PUBLIC, false = PRIVATE (default)
    mapping(uint256 => bool) private _isPublic;

    /// @notice Optional delegate per token who can toggle visibility
    mapping(uint256 => address) private _delegates;

    /// @notice Per-token schema version override (0 = use global)
    mapping(uint256 => uint256) private _tokenSchemaVersion;

    /// @notice Per-token metadata nonce for cache-busting
    mapping(uint256 => uint64) private _metadataNonce;

    /// @notice Mapping from address to their token ID (0 = no token)
    mapping(address => uint256) public tokenOf;

    // ============ Constructor ============
    
    /**
     * @notice Initializes the AEra Profile NFT contract
     * @param admin Address to receive DEFAULT_ADMIN_ROLE
     * @param _basePublicURI Initial base URI for public metadata
     * @param _basePrivateURI Initial base URI for private/placeholder metadata
     * @param contractURI_ Initial contract-level metadata URI
     */
    constructor(
        address admin,
        string memory _basePublicURI,
        string memory _basePrivateURI,
        string memory contractURI_
    ) ERC721("AEra Profile", "APR") {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        // MINTER for Base mainnet
        _grantRole(MINTER_ROLE, 0x22A2cAcB19e77D25DA063A787870A3eE6BAC8Dfe);

        basePublicURI = _basePublicURI;
        basePrivateURI = _basePrivateURI;
        _contractURI = contractURI_;
        metadataSchemaVersion = 1;
        _nextTokenId = 1;
    }

    // ============ Minting ============

    /**
     * @notice Mints a new profile token to the specified address
     * @dev Enforces one NFT per wallet
     * @param to Recipient address
     * @return tokenId The newly minted token ID
     */
    function mint(address to) external onlyRole(MINTER_ROLE) whenNotPaused returns (uint256 tokenId) {
        if (to == address(0)) revert ZeroAddress();
        if (tokenOf[to] != 0) revert AlreadyHasProfile();
        
        tokenId = _nextTokenId++;
        _safeMint(to, tokenId);
        tokenOf[to] = tokenId;
        
        emit Minted(to, tokenId);
    }

    // ============ Burning ============

    /**
     * @notice Allows token owner to burn their profile token
     * @param tokenId Token to burn
     */
    function burn(uint256 tokenId) external {
        _requireTokenExists(tokenId);
        address owner = ownerOf(tokenId);
        if (owner != msg.sender) revert NotTokenOwner();
        
        // Clean up token-specific storage
        delete _isPublic[tokenId];
        delete _delegates[tokenId];
        delete _tokenSchemaVersion[tokenId];
        delete _metadataNonce[tokenId];
        delete tokenOf[owner];
        
        _burn(tokenId);
        
        emit Burned(tokenId);
    }

    // ============ Visibility Management ============

    /**
     * @notice Set visibility for a token (only owner or delegate)
     * @param tokenId Token to modify
     * @param isPublic True for PUBLIC, false for PRIVATE
     */
    function setVisibility(uint256 tokenId, bool isPublic) external {
        _requireTokenExists(tokenId);
        
        address owner = ownerOf(tokenId);
        if (msg.sender != owner && msg.sender != _delegates[tokenId]) {
            revert NotTokenOwnerOrDelegate();
        }
        
        _isPublic[tokenId] = isPublic;
        
        emit VisibilityChanged(tokenId, isPublic);
        emit MetadataUpdate(tokenId); // EIP-4906: notify indexers
    }

    /**
     * @notice Check if a token's metadata is public
     * @param tokenId Token to check
     * @return True if public, false if private
     */
    function isPublic(uint256 tokenId) external view returns (bool) {
        _requireTokenExists(tokenId);
        return _isPublic[tokenId];
    }

    // ============ Delegation ============

    /**
     * @notice Set a delegate who can toggle visibility for your token
     * @param tokenId Token to set delegate for
     * @param delegate Address of the delegate (address(0) to clear)
     */
    function setDelegate(uint256 tokenId, address delegate) external {
        _requireTokenExists(tokenId);
        if (ownerOf(tokenId) != msg.sender) revert NotTokenOwner();
        
        _delegates[tokenId] = delegate;
        
        emit DelegateChanged(tokenId, delegate);
    }

    /**
     * @notice Get the delegate for a token
     * @param tokenId Token to query
     * @return Delegate address (address(0) if none)
     */
    function getDelegate(uint256 tokenId) external view returns (address) {
        _requireTokenExists(tokenId);
        return _delegates[tokenId];
    }

    // ============ Token URI ============

    /**
     * @notice Returns the metadata URI for a token
     * @dev Returns private URI if token is PRIVATE, public URI if PUBLIC
     *      Includes nonce parameter for cache-busting
     * @param tokenId Token to get URI for
     * @return Metadata URI string
     */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireTokenExists(tokenId);
        
        string memory baseURI = _isPublic[tokenId] ? basePublicURI : basePrivateURI;
        uint64 nonce = _metadataNonce[tokenId];
        
        if (nonce > 0) {
            return string(abi.encodePacked(
                baseURI, "/", tokenId.toString(), ".json?v=", uint256(nonce).toString()
            ));
        }
        return string(abi.encodePacked(baseURI, "/", tokenId.toString(), ".json"));
    }

    /**
     * @notice Bump metadata nonce to force cache refresh
     * @dev Can be called by owner, delegate, or admin
     * @param tokenId Token to bump nonce for
     */
    function bumpMetadataNonce(uint256 tokenId) external {
        _requireTokenExists(tokenId);
        
        address owner = ownerOf(tokenId);
        if (msg.sender != owner && 
            msg.sender != _delegates[tokenId] && 
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotTokenOwnerOrDelegate();
        }
        
        unchecked {
            _metadataNonce[tokenId]++;
        }
        
        emit MetadataUpdate(tokenId);
    }

    /**
     * @notice Get current metadata nonce for a token
     * @param tokenId Token to query
     * @return Current nonce value
     */
    function getMetadataNonce(uint256 tokenId) external view returns (uint64) {
        _requireTokenExists(tokenId);
        return _metadataNonce[tokenId];
    }

    // ============ Schema Versioning ============

    /**
     * @notice Get the effective schema version for a token
     * @param tokenId Token to query
     * @return Schema version (token override if set, otherwise global)
     */
    function getSchemaVersion(uint256 tokenId) external view returns (uint256) {
        _requireTokenExists(tokenId);
        uint256 tokenVersion = _tokenSchemaVersion[tokenId];
        return tokenVersion > 0 ? tokenVersion : metadataSchemaVersion;
    }

    /**
     * @notice Set per-token schema version override (admin only)
     * @param tokenId Token to modify
     * @param version Schema version (0 to use global)
     */
    function setTokenSchemaVersion(uint256 tokenId, uint256 version) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        _requireTokenExists(tokenId);
        _tokenSchemaVersion[tokenId] = version;
        
        emit TokenSchemaVersionChanged(tokenId, version);
    }

    // ============ Admin Functions ============

    /**
     * @notice Update base URIs for metadata
     * @param _basePublicURI New public metadata base URI
     * @param _basePrivateURI New private metadata base URI
     */
    function setBaseURIs(string calldata _basePublicURI, string calldata _basePrivateURI) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        basePublicURI = _basePublicURI;
        basePrivateURI = _basePrivateURI;
        
        emit BaseURIsChanged(_basePublicURI, _basePrivateURI);
        
        // EIP-4906: notify indexers that all metadata may have changed
        if (_nextTokenId > 1) {
            emit BatchMetadataUpdate(1, _nextTokenId - 1);
        }
    }

    /**
     * @notice Returns contract-level metadata URI for OpenSea
     * @dev OpenSea reads this as a function, not a public variable
     * @return Contract metadata URI
     */
    function contractURI() external view returns (string memory) {
        return _contractURI;
    }

    /**
     * @notice Update contract-level metadata URI
     * @param contractURI_ New contract metadata URI
     */
    function setContractURI(string calldata contractURI_) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        _contractURI = contractURI_;
    }

    /**
     * @notice Update global metadata schema version
     * @param version New schema version
     */
    function setMetadataSchemaVersion(uint256 version) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        metadataSchemaVersion = version;
        
        emit SchemaVersionChanged(version);
    }

    /**
     * @notice Enable or disable soulbound mode
     * @param enabled True to enable soulbound mode (block transfers)
     */
    function setSoulboundMode(bool enabled) external onlyRole(DEFAULT_ADMIN_ROLE) {
        soulboundMode = enabled;
        
        emit SoulboundModeChanged(enabled);
    }

    /**
     * @notice Pause minting
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause minting
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============ Transfer Restrictions (Soulbound) ============

    /**
     * @dev Hook to enforce soulbound mode and update tokenOf mapping
     * Blocks transfers when soulbound mode is enabled, except for mint (from=0) and burn (to=0)
     * Also clears delegate on transfer (security: delegate is owner-bound)
     */
    function _update(address to, uint256 tokenId, address auth) 
        internal 
        override 
        returns (address) 
    {
        address from = _ownerOf(tokenId);
        
        // Allow mint (from == 0) and burn (to == 0) even in soulbound mode
        if (soulboundMode && from != address(0) && to != address(0)) {
            revert SoulboundTransferBlocked();
        }
        
        // Clear delegate on transfer (not on mint/burn) - security feature
        if (from != address(0) && to != address(0)) {
            if (_delegates[tokenId] != address(0)) {
                delete _delegates[tokenId];
                emit DelegateChanged(tokenId, address(0));
            }
            // Update tokenOf mapping for transfers
            delete tokenOf[from];
            tokenOf[to] = tokenId;
        }
        
        return super._update(to, tokenId, auth);
    }

    /**
     * @dev Block approvals in soulbound mode for clearer UX
     */
    function approve(address to, uint256 tokenId) public override {
        if (soulboundMode) revert SoulboundApprovalBlocked();
        super.approve(to, tokenId);
    }

    /**
     * @dev Block operator approvals in soulbound mode for clearer UX
     */
    function setApprovalForAll(address operator, bool approved) public override {
        if (soulboundMode && approved) revert SoulboundApprovalBlocked();
        super.setApprovalForAll(operator, approved);
    }

    // ============ View Functions ============

    /**
     * @notice Get total number of tokens minted (including burned)
     * @return Total tokens ever minted
     */
    function totalMinted() external view returns (uint256) {
        return _nextTokenId - 1;
    }

    /**
     * @notice Get the next token ID that will be minted
     * @return Next token ID
     */
    function nextTokenId() external view returns (uint256) {
        return _nextTokenId;
    }

    // ============ Interface Support ============

    /**
     * @dev See {IERC165-supportsInterface}
     * Includes EIP-4906 support for metadata update events
     */
    function supportsInterface(bytes4 interfaceId) 
        public 
        view 
        override(ERC721, AccessControl, IERC165) 
        returns (bool) 
    {
        return 
            interfaceId == bytes4(0x49064906) || // EIP-4906
            super.supportsInterface(interfaceId);
    }

    // ============ Internal Helpers ============

    /**
     * @dev Reverts if token does not exist
     */
    function _requireTokenExists(uint256 tokenId) internal view {
        if (_ownerOf(tokenId) == address(0)) revert TokenDoesNotExist();
    }
}
