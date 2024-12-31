package com.eb.rouyi.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.eb.constant.enums.RuoyiEnableStatusEnums;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.Date;

@TableName("sys_user")
@Data
public class SysUserEntity implements Serializable {
    private static final long serialVersionUID = 1061442663731369916L;

    public static boolean isAdmin(Long userId) {
        return userId != null && 1L == userId;
    }

    @TableId(type = IdType.AUTO)
    private Long id;

    @Size(max = 64)
    private String username;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Size(max = 64)
    private String password;

    @Size(max = 64)
    private String nickname;

    @JsonIgnore
    private String salt;

    /**
     * 二次认证key
     */
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private String twoFactorAuthKey;

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Date created;

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Date updated;

    /** 部门ID */
    private Long deptId;

    /** 部门父ID */
    private Long parentId;

    /** 角色ID */
    private Long roleId;

    /** 用户类型 */
    private String userType;

    /** 用户邮箱 */
    @Email(message = "邮箱格式不正确")
    @Size(min = 0, max = 50, message = "邮箱长度不能超过50个字符")
    private String email;

    /** 手机号码 */
    private String phonenumber;

    /** 用户性别 */
    private String sex;

    /** 用户头像 */
    private String avatar;

    /** 帐号状态（0正常 1停用） */
    private RuoyiEnableStatusEnums status;

    /** 删除标志（0代表存在 2代表删除） */
    private String delFlag;

    /** 最后登录IP */
    private String loginIp;

    /** 最后登录时间 */
    private Date loginDate;

    /** 密码最后更新时间 */
    private Date pwdUpdateDate;

    private String remark;

    private String createBy;

    private String updateBy;
}
