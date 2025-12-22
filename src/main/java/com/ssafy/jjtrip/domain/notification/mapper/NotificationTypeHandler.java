package com.ssafy.jjtrip.domain.notification.mapper;

import com.ssafy.jjtrip.domain.notification.entity.NotificationType;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@MappedTypes(NotificationType.class)
public class NotificationTypeHandler extends BaseTypeHandler<NotificationType> {

    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, NotificationType parameter, JdbcType jdbcType) throws SQLException {
        ps.setString(i, parameter.name());
    }

    @Override
    public NotificationType getNullableResult(ResultSet rs, String columnName) throws SQLException {
        String name = rs.getString(columnName);
        return name == null ? null : NotificationType.valueOf(name);
    }

    @Override
    public NotificationType getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        String name = rs.getString(columnIndex);
        return name == null ? null : NotificationType.valueOf(name);
    }

    @Override
    public NotificationType getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        String name = cs.getString(columnIndex);
        return name == null ? null : NotificationType.valueOf(name);
    }
}
