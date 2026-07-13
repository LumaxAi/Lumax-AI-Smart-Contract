// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @dev OpenZeppelin Contracts Context and IERC20/Ownable basic implementation
 * Optimized and Secured for Lumax AI (LMAX)
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}

interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract Ownable is Context {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _transferOwnership(_msgSender());
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }

    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

contract LumaxAI is Context, IERC20, Ownable {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    mapping(address => bool) private _isBlacklisted;

    string private constant _name = "Lumax AI";
    string private constant _symbol = "LMAX";
    uint8 private constant _decimals = 18;
    uint256 private constant _totalSupply = 5000000 * 10**18; // 5 Million Total Supply

    bool public tradingEnabled = false;
    bool public limitsEnabled = true;

    uint256 public maxTxAmount = 25000 * 10**18;  // 0.5% of total supply
    uint256 public maxWalletSize = 50000 * 10**18; // 1% of total supply

    constructor() {
        _balances[_msgSender()] = _totalSupply;
        emit Transfer(address(0), _msgSender(), _totalSupply);
    }

    function name() public view virtual returns (string memory) {
        return _name;
    }

    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    function decimals() public view virtual returns (uint8) {
        return _decimals;
    }

    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 value) public virtual override returns (bool) {
        address owner = _msgSender();
        _transfer(owner, to, value);
        return true;
    }

    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 value) public virtual override returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public virtual override returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, value);
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal virtual {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");
        require(!_isBlacklisted[from], "LumaxAI: Sender is blacklisted");
        require(!_isBlacklisted[to], "LumaxAI: Recipient is blacklisted");

        if (!tradingEnabled && from != owner() && to != owner()) {
            revert("LumaxAI: Trading is not enabled yet");
        }

        if (limitsEnabled && from != owner() && to != owner()) {
            require(value <= maxTxAmount, "LumaxAI: Exceeds max transaction amount");
            require(_balances[to] + value <= maxWalletSize, "LumaxAI: Exceeds max wallet size");
        }

        uint256 fromBalance = _balances[from];
        require(fromBalance >= value, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[from] = fromBalance - value;
            _balances[to] += value;
        }

        emit Transfer(from, to, value);
    }

    function _approve(address owner, address spender, uint256 value) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function _spendAllowance(address owner, address spender, uint256 value) internal virtual {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= value, "ERC20: insufficient allowance");
            unchecked {
                _approve(owner, spender, currentAllowance - value);
            }
        }
    }

    /**
     * @dev Admin Control Functions
     */

    // Multi-send / AirDrop feature
    function multiSend(address[] calldata recipients, uint256[] calldata amounts) external onlyOwner {
        require(recipients.length == amounts.length, "LumaxAI: Mismatched input lengths");
        for (uint256 i = 0; i < recipients.length; i++) {
            _transfer(_msgSender(), recipients[i], amounts[i] * 10**18);
        }
    }

    // Toggle trading status for anti-bot launch
    function setTradingStatus(bool _status) external onlyOwner {
        tradingEnabled = _status;
    }

    // Permanently disable wallet/transaction limits
    function disableLimits() external onlyOwner {
        limitsEnabled = false;
    }

    // Manage blacklist for malicious bots
    function blacklistAddress(address account, bool value) external onlyOwner {
        _isBlacklisted[account] = value;
    }

    // Check blacklist status
    function isBlacklisted(address account) public view returns (bool) {
        return _isBlacklisted[account];
    }
}
