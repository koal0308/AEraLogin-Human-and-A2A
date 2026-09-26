// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title AEraIdentityNFT
 * @dev Soul-bound Identity NFT for AEra system
 * @notice One NFT per wallet, non-transferable (soul-bound)
 */
contract AEraIdentityNFT is ERC721, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant STATUS_ROLE = keccak256("STATUS_ROLE");

    enum Status {
        ACTIVE,
        SUSPENDED,
        REVOKED
    }

    struct Identity {
        uint256 tokenId;
        address wallet;
        uint256 createdAt;
        Status status;
    }

    uint256 private _tokenIdCounter;
    mapping(address => uint256) private _walletToTokenId;
    mapping(uint256 => Status) private _tokenStatus;

    event IdentityMinted(address indexed wallet, uint256 indexed tokenId);
    event IdentityBurned(uint256 indexed tokenId, address indexed wallet);
    event StatusChanged(uint256 indexed tokenId, Status oldStatus, Status newStatus);
    event IdentityRelocated(uint256 indexed tokenId, address indexed oldWallet, address indexed newWallet);

    error ApprovalNotAllowed();
    error TransferNotAllowed();
    error AlreadyHasIdentity();
    error NoIdentityFound();
    error InvalidStatus();

    constructor(address aeraSafe) ERC721("AEra Identity", "AERA-ID") {
        _grantRole(DEFAULT_ADMIN_ROLE, aeraSafe);
        _grantRole(MINTER_ROLE, aeraSafe);
        _grantRole(STATUS_ROLE, aeraSafe);
    }

    /**
     * @dev Mint a new identity NFT
     * @param wallet The wallet address to mint for
     * @return tokenId The newly minted token ID
     */
    function mintIdentity(address wallet) external onlyRole(MINTER_ROLE) returns (uint256) {
        if (_walletToTokenId[wallet] != 0) revert AlreadyHasIdentity();
        
        _tokenIdCounter++;
        uint256 tokenId = _tokenIdCounter;
        
        _safeMint(wallet, tokenId);
        _walletToTokenId[wallet] = tokenId;
        _tokenStatus[tokenId] = Status.ACTIVE;
        
        emit IdentityMinted(wallet, tokenId);
        return tokenId;
    }

    /**
     * @dev Burn an identity NFT
     * @param tokenId The token ID to burn
     */
    function burnIdentity(uint256 tokenId) external onlyRole(STATUS_ROLE) {
        address wallet = ownerOf(tokenId);
        _burn(tokenId);
        delete _walletToTokenId[wallet];
        delete _tokenStatus[tokenId];
        
        emit IdentityBurned(tokenId, wallet);
    }

    /**
     * @dev Set the status of an identity
     * @param tokenId The token ID
     * @param newStatus The new status
     */
    function setStatus(uint256 tokenId, Status newStatus) external onlyRole(STATUS_ROLE) {
        Status oldStatus = _tokenStatus[tokenId];
        _tokenStatus[tokenId] = newStatus;
        
        emit StatusChanged(tokenId, oldStatus, newStatus);
    }

    /**
     * @dev Relocate an identity to a new wallet (admin only)
     * @param tokenId The token ID
     * @param newWallet The new wallet address
     */
    function relocateIdentity(uint256 tokenId, address newWallet) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_walletToTokenId[newWallet] != 0) revert AlreadyHasIdentity();
        
        address oldWallet = ownerOf(tokenId);
        
        _update(newWallet, tokenId, address(0));
        
        delete _walletToTokenId[oldWallet];
        _walletToTokenId[newWallet] = tokenId;
        
        emit IdentityRelocated(tokenId, oldWallet, newWallet);
    }

    /**
     * @dev Get token ID by wallet address
     * @param wallet The wallet address
     * @return tokenId The token ID (0 if none)
     */
    function getTokenIdByWallet(address wallet) external view returns (uint256) {
        return _walletToTokenId[wallet];
    }

    /**
     * @dev Get status of a token
     * @param tokenId The token ID
     * @return status The token status
     */
    function getStatus(uint256 tokenId) external view returns (Status) {
        return _tokenStatus[tokenId];
    }

    /**
     * @dev Check if wallet has an active identity
     * @param wallet The wallet address
     * @return hasActive True if wallet has an active identity
     */
    function hasActiveIdentity(address wallet) external view returns (bool) {
        uint256 tokenId = _walletToTokenId[wallet];
        return tokenId != 0 && _tokenStatus[tokenId] == Status.ACTIVE;
    }

    // ========== SOUL-BOUND: Disable Transfers ==========

    function approve(address, uint256) public pure override {
        revert ApprovalNotAllowed();
    }

    function setApprovalForAll(address, bool) public pure override {
        revert ApprovalNotAllowed();
    }

    function transferFrom(address, address, uint256) public pure override {
        revert TransferNotAllowed();
    }

    function safeTransferFrom(address, address, uint256) public pure override {
        revert TransferNotAllowed();
    }

    function safeTransferFrom(address, address, uint256, bytes memory) public pure override {
        revert TransferNotAllowed();
    }

    // ========== ERC-165 Support ==========

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
